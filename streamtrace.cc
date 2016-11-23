/*-
 * Copyright (c) 2015 David T. Chisnall
 *
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249
 * ("MRC2"), as part of the DARPA MRC research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

#include "streamtrace.hh"
#include "disassembler.hh"
#include <thread>
#include <mutex>
#include <future>
#include <atomic>
#include <algorithm>
#include <limits>
#include <condition_variable>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <lzma.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>

#define expect(x, y)      __builtin_expect(!!(x), y)


using namespace cheri;
using namespace streamtrace;

trace::~trace() {}

namespace {

/**
 * State object for fast enumeration, modelled on NSFastEnumerationState.  This
 * allows the enumerated object to provide direct access to internal values.
 */
template<typename T, int buffer_size=4096>
struct fast_enumeration_state
{
	/**
	 * Size of the buffer inside this structure.  This allows external users to
	 * determine the template parameter easily.
	 */
	static const int internal_buffer_size = buffer_size;
	/**
	 * State for use by the enumerated object.
	 */
	uintptr_t state[2] = {0,0};
	/**
	 * The number of elements that have been returned.
	 */
	size_t size = 0;
	/**
	 * A pointer to `size` objects of type `T`.  This is used by callers to
	 * look up entries and can be set by callees to either:
	 *
	 * - The internal buffer.
	 * - The shared buffer.
	 * - An buffer internal to the callee.
	 *
	 * In all cases, the contents of the buffer must not be immutable.
	 */
	T *ptr = nullptr;
	/**
	 * A pointer to a buffer that the callee can use to store some other value.
	 */
	std::shared_ptr<T> shared_buffer;
	/**
	 * An internal buffer that the callee can copy data into, if required.
	 */
	T buffer[buffer_size];
	/**
	 * Begin method allowing this to be used with range-based for loops.
	 */
	T* begin()
	{
		return ptr;
	}
	/**
	 * End method allowing this to be used with range-based for loops.
	 */
	T* end()
	{
		return ptr + size;
	}
	/**
	 * Assignment operator.
	 */
	fast_enumeration_state<T,buffer_size>& operator=(const fast_enumeration_state<T,buffer_size>& o)
	{
		size = o.size;
		ptr = o.ptr;
		shared_buffer = o.shared_buffer;
		memcpy(buffer, o.buffer, sizeof(buffer));
		return *this;
	}
};

/**
 * Interface for classes that support fast enumeration.
 */
template<class T, int buffer_size=4096>
struct fast_enumeration
{
	/**
	 * The state for this form of fast enumeration.
	 */
	typedef fast_enumeration_state<T,buffer_size> enumerator;
	/**
	 * Method that fills in fast enumeration state starting at a specified
	 * object.
	 */
	virtual bool enumerate(enumerator &e, size_t start) = 0;
	virtual ~fast_enumeration() {}
};

/**
 * Method for fast enumeration within a range.
 */
template<typename T, typename B>
void fast_enumerate(B &o,
                    std::function<bool(size_t,T&)> fn,
                    size_t start=0,
                    size_t end=std::numeric_limits<size_t>::max())
{
	typename B::enumerator e;
	while ((start < end) && o.enumerate(e, start))
	{
		for (T &v : e)
		{
			fn(start++, v);
			if (start >= end)
			{
				break;
			}
		}
	}
}

/**
 * Class encapsulating the machine state at a specific point in the trace.  A
 * trace object stores instances of this class at points along the trace,
 * allowing the state in between to be quickly inferred.
 */
struct keyframe
{
	/**
	 * The total number of elapsed cycles in the trace.
	 */
	uint64_t cycles = 0;
	/**
	 * Program counter for the current location.
	 */
	uint64_t pc = 0;
	/**
	 * The current value of the 10-bit cycle counter.
	 */
	uint16_t cycle_counter = 0;
	/**
	 * The register set.
	 */
	register_set regs;
	/**
	 * Updates the state for a new trace entry.  The disassembler is used to
	 * determine the target register for the instruction.
	 */
	void update(const debug_trace_entry &, disassembler::disassembler &);
};

/**
 * An in-memory segment of a trace.  To speed up random access (assuming some
 * locality of reference), the `concrete_streamtrace` class loads the trace in
 * segments.
 */
class trace_segment {
	/**
	 * Adds a new entry to the end of this trace segment.  This exists so that
	 * the code doesn't need duplicating between template variants.
	 */
	void add_entry(disassembler::disassembler &d,
	               keyframe &,
	               const debug_trace_entry &);
	public:
	/**
	 * The register sets within this segment, one per step in the trace.
	 */
	std::vector<register_set>      regs;
	/**
	 * The trace entries for this segment.
	 */
	std::vector<debug_trace_entry> entries;
	/**
	 * Construct a trace segment from a sequence of trace entries.
	 */
	template<class T>
	trace_segment(disassembler::disassembler &d, keyframe rs, T &&begin, T &&end)
	{
		assert(begin != end);
		while (begin != end)
		{
			debug_trace_entry entry(*begin, d);
			add_entry(d, rs, entry);
			++begin;
		}
	}
};

/**
 * A map from a range of indexes 0-n to an increasing set of indexes to another
 * range of linear indexes.  This is used to densely store the mapping from
 * indexes in trace views to indexes in the underlying trace.
 */
class index_map
{
	/**
	 * A range of indexes.
	 */
	struct range
	{
		/**
		 * The first index in the range.
		 */
		uint64_t start;
		/**
		 * The last index in the range (not one after).
		 */
		uint64_t end;
	};
	/**
	 * An entry in the range map.
	 */
	struct range_map_entry
	{
		/**
		 * The source range in a range map entry.
		 */
		range from;
		/**
		 * The range that the from entry maps to.
		 */
		// Note: The end can always be calculated from the from field, so if
		// profiling shows that these consume a lot of RAM then we can save
		// memory by 25% quite easily.
		range to;
	};
	/**
	 * The type used to store the range map entries.  This needs fast random
	 * access on a sequential store, as we will do a binary search.
	 */
	typedef std::vector<range_map_entry> range_map;
	/**
	 * The vector of ranges stored by this index map.
	 */
	range_map ranges;
	/**
	 * Private constructor, takes ownership of a temporary range map
	 * constructed by the caller.
	 */
	index_map(range_map &&m) : ranges(m) {}
	/**
	 * Look up a source index and return an iterator to the range containing
	 * it.
	 */
	decltype(ranges)::iterator find_idx(uint64_t idx)
	{
		auto r = std::lower_bound(ranges.begin(), ranges.end(), idx,
			[](const range_map_entry e, const uint64_t v) {
				return e.from.end < v;
			});
		return r;
	}
	public:
	/**
	 * default constructor.
	 */
	index_map() {}
	/**
	 * Range map iterator.  This is a ForwardIterator.
	 */
	class iterator
	{
		friend class index_map;
		/**
		 * The current index that we're looking at.
		 */
		uint64_t idx;
		/**
		 * The start of the contiguous range of source addresses that we're
		 * inspecting.
		 */
		uint64_t from_base = 0;
		/**
		 * The start of the contiguous range of destination addresses that
		 * corresponds to `from_base`.
		 */
		uint64_t to_base = 0;
		/**
		 * The top of the range.  One after the maximum input value in this
		 * contiguous range.
		 */
		uint64_t top = 0;
		/**
		 * The container that this iterator refers to.
		 */
		index_map &container;
		/**
		 * After updating the index, recalculate the base and top values used
		 * to compute the target range.
		 */
		inline void recalculate()
		{
			if ((idx >= from_base) && (idx < top))
			{
				return;
			}
			auto i = container.find_idx(idx);
			if (i == container.ranges.end())
			{
				top = 0;
				return;
			}
			from_base = i->from.start;
			to_base = i->to.start;
			top = i->from.end+1;
		}
		iterator(index_map &m, uint64_t i) : idx(i), container(m)
		{
			recalculate();
		}
		public:
		iterator &operator++() {
			idx++;
			recalculate();
			return *this;
		}
		iterator &operator+=(uint64_t off) {
			idx+=off;
			recalculate();
			return *this;
		}
		iterator operator+(uint64_t off) {
			iterator n(container, idx+off);
			return n;
		}
		/**
		 * Difference with another operator.
		 */
		uint64_t operator-(const iterator& other) {
			assert(&container == &other.container);
			return idx - other.idx;
		}
		/**
		 * Dereference the iterator, giving a destination index.
		 */
		uint64_t operator*() const {
			if (top < idx)
			{
				return -1;
			}
			return idx - from_base + to_base;
		}
		/**
		 * Compare iterators for equality.  Used to determine the end of iteration.
		 */
		bool operator!=(iterator &other)
		{
			assert(&container == &other.container);
			return idx != other.idx;
		}
	};
	/**
	 * Add a new destination address.  The new destination address is
	 * automatically associated with a new source address that immediately
	 * follow the last one already in the map.
	 */
	void push_back(uint64_t v)
	{
		if (ranges.size() == 0)
		{
			range_map_entry dst = { {0,0}, {v, v} };
			ranges.push_back(dst);
			return;
		}
		auto &e = ranges.back();
		// If we're adding the next entry, then just stick it in the range map.
		if (e.to.end+ 1 == v)
		{
			e.from.end++;
			e.to.end++;
			return;
		}
		// If there's a gap, then insert a new range.
		range_map_entry n;
		n.from.start = n.from.end = e.from.end+1;
		n.to.start = n.to.end = v;
		ranges.push_back(n);
	}
	/**
	 * Returns a new map that contains all of the destination indexes that are
	 * not in the source.  The `length` parameter gives the number of
	 * destination indexes that exist.
	 */
	index_map inverted_map(uint64_t length)
	{
		range_map inverted;
		if (ranges.size() == 0)
		{
			range_map_entry dst = { {0,length}, {0, length} };
			inverted.push_back(dst);
			index_map inverted_map(std::move(inverted));
			return inverted_map;
		}
		const auto src = ranges.front();
		range_map_entry dst { {0,0},{0,0}};
		if (src.to.start == 0)
		{
			dst.to.start = dst.to.end = src.to.end+1;
		}
		else
		{
			dst.to.end = src.to.start-1;
		}
		for (auto i=ranges.begin()+1, e=ranges.end() ; i!=e ; ++i)
		{
			dst.to.end = i->to.start - 1;
			dst.from.end = dst.from.start + dst.to.end - dst.to.start;
			inverted.push_back(dst);
			dst.from.start = dst.from.end + 1;
			dst.from.end = dst.from.end;
			dst.to.start = i->to.end + 1;
		}
		if (dst.from.start < length)
		{
			dst.to.end = length - 1;
			dst.from.end = dst.from.start + dst.to.end - dst.to.start;
			inverted.push_back(dst);
		}
		index_map inverted_map(std::move(inverted));
		return inverted_map;
	}
	/**
	 * Return the destination index that corresponds to this source index.
	 * Undefined if the source index is not in this map.
	 */
	uint64_t operator [](uint64_t idx)
	{
		auto i = find_idx(idx);
		if (i == ranges.end())
		{
			return -1;
		}
		return idx - i->from.start + i->to.start;
	}
	/**
	 * Returns the number of elements in this map.
	 */
	uint64_t size()
	{
		if (ranges.size() == 0)
		{
			return 0;
		}
		return ranges.back().from.end+1;
	}
	/**
	 * Iterator to the start of the map.  Iterators are dereferenced to give
	 * *destination* addresses and so can be used to index into the target.
	 */
	iterator begin()
	{
		iterator i(*this, 0);
		return i;
	}
	/**
	 * End iterator.
	 */
	iterator end()
	{
		iterator i(*this, size());
		return i;
	}
};

template<class T>
class concrete_traceview;


bool scan_range(uint64_t &start, uint64_t &scan_end, int opts, int &outinc, uint64_t len)
{
	scan_end = std::min(scan_end+1, len);
	if (scan_end < start)
	{
		return false;
	}
	outinc = 1;
	// If we're scanning forwards
	if (opts & cheri::streamtrace::trace::backwards)
	{
		outinc = -1;
		scan_end--;
		start--;
		std::swap(start, scan_end);
	}
	return true;
}
/**
 * Number of entries between keyframes.  Note that each keyframe is over 1KB
 * (including the complete capability register set size) and making this value
 * larger can cause significant memory use.
 */
const uint64_t keyframe_interval = 1<<11;
/**
 * Concrete subclass of the streamtrace.  Manages trace segments.
 */
template<class T>
class concrete_streamtrace : public trace,
                             public std::enable_shared_from_this<concrete_streamtrace<T>>
{
	friend class concrete_traceview<T>;
	/**
	 * Iterators to the beginning and end of the stream.
	 */
	T begin, end;
	/**
	 * Start of the current cached segment.
	 */
	uint64_t segment_start = -1;
	/**
	 * The offset within the current segment of the trace entry currently being
	 * inspected.
	 */
	uint64_t segment_offset = 0;
	/**
	 * Decoded segment of the trace.
	 */
	std::unique_ptr<trace_segment> cache;
	/**
	 * Keyframes, used for random access into the stream.
	 * Note: For streamtraces that we're going to want to look at a lot, we
	 * could dump these to disk.
	 */
	std::vector<keyframe> keyframes;
	/**
	 * Lock that protects the keyframes field while the preloading thread is
	 * running.  This is not used once finished_loading is true.
	 */
	std::mutex keyframe_lock;
	/**
	 * Flag that we have completed computing keyframes for the entire trace.
	 */
	std::atomic<bool>    finished_loading = { false };
	/**
	 * Flag to kill the perload thread if the trace is finished.
	 */
	std::atomic<bool>    cancel = { false };
	/**
	 * Condition variable used to allow the main thread to wait for the
	 * preloading thread to catch up.
	 */
	std::condition_variable notify;
	/**
	 * The thread that computes the keyframes for faster random access.
	 */
	std::thread preload_thread;
	/**
	 * The disassembler used when materialising trace entries.
	 */
	disassembler::disassembler disass;
	/**
	 * The callback that will be invoked when preloading.
	 */
	notifier callback;
	/**
	 * Scans the entire streamtrace and records keyframes for faster seeking.
	 *
	 * This method is expected to be invoked precisely once, from another
	 * thread.
	 */
	void preload()
	{
		assert(!finished_loading);
		keyframe kf;
		disassembler::disassembler d;
		// On the first loop iteration, we want to push the keyframe into the
		// list
		int frame = 1;
		uint64_t frames_loaded = 0;
		for (T i=begin ; i!=end ; ++i)
		{
			frames_loaded++;
			if (cancel)
			{
				return;
			}
			debug_trace_entry e(*i, d);
			kf.update(e, d);
			if (--frame == 0)
			{
				frame = keyframe_interval;
				std::lock_guard<std::mutex> lock(keyframe_lock);
				keyframes.push_back(kf);
				notify.notify_all();
				if (callback && callback(this,  frames_loaded, false))
				{
					break;
				}
			}
		}
		if (callback)
		{
			callback(this,  frames_loaded, true);
		}
		finished_loading = true;
		notify.notify_all();
	}
	/**
	 * Returns the keyframe associated with a specific offset.  This is
	 * thread-safe with respect to a thread running the `preload()` method.  It
	 * will block until preloading is finished.
	 */
	keyframe get_keyframe(uint64_t offset)
	{
		offset /= keyframe_interval;
		// This looks racy, but is permitted because finished_loading never
		// transition from true to false.  Once it has become true, we do not
		// need to do any locking to access the keyframes vector.
		if (finished_loading)
		{
			return keyframes[offset];
		}
		std::unique_lock<std::mutex> lock(keyframe_lock);
		if (finished_loading || keyframes.size() > offset)
		{
			return keyframes[offset];
		}
		notify.wait(lock, [&]() { return finished_loading || keyframes.size() > offset; });
		return keyframes[offset];
	}
	/**
	 * Load a cached segment that we can iterate over.  This constructs a new
	 * segment and so is safe to call from multiple threads (e.g. in the
	 * `trace` methods).
	 */
	std::unique_ptr<trace_segment> create_segment_for_index(uint64_t offset)
	{
		auto kf = get_keyframe(offset);
		uint64_t segstart = (offset / keyframe_interval) * keyframe_interval;
		uint64_t length = std::min(keyframe_interval, (end - begin) - segstart);
		T segment_begin = begin + segstart;
		T segment_end = segment_begin + length;
		return std::unique_ptr<trace_segment>(new trace_segment(disass, kf,
		                   std::move(segment_begin), std::move(segment_end)));
	}
	bool cache_segment(uint64_t offset)
	{
		if (offset / keyframe_interval == (segment_start / keyframe_interval))
		{
			return true;
		}
		if (offset > end-begin)
		{
			return false;
		}
		segment_start = (offset / keyframe_interval) * keyframe_interval;
		cache = std::move(create_segment_for_index(offset));
		return true;
	}
	public:
	/**
	 * Construct a streamtrace from two iterators.
	 */
	concrete_streamtrace(T &&b, T &&e, notifier fn) : begin(b), end(e), callback(fn)
	{
		preload_thread = std::thread([&] { preload(); });
	}
	~concrete_streamtrace()
	{
		cancel = true;
		preload_thread.join();
	}
	uint64_t size() override
	{
		return end-begin;
	}
	uint64_t instruction_number_for_index(uint64_t idx) override
	{
		return idx;
	}
	void scan(scanner fn, uint64_t start, uint64_t scan_end, int opts) override
	{
		int inc;
		disassembler::disassembler d;
		if (!scan_range(start, scan_end, opts, inc, end-begin))
		{
			return;
		}
		for (T i=begin+start,e=begin+scan_end ; i!=e ; i+=inc)
		{
			debug_trace_entry te(*i, d);
			if (fn(te, start))
			{
				return;
			}
			start += inc;
		}
	}
	void scan(detailed_scanner fn, uint64_t start, uint64_t scan_end, int opts=0) override
	{
		int inc;
		if (!scan_range(start, scan_end, opts, inc, end-begin))
		{
			return;
		}
		uint64_t segstart = -1;
		std::unique_ptr<trace_segment> segment;
		for (; start<scan_end ; start+=inc)
		{
			if (segstart != (start / keyframe_interval))
			{
				segment = std::move(create_segment_for_index(start));
				segstart = (start / keyframe_interval);
			}
			uint64_t offset = start % keyframe_interval;
			auto &regs = segment->regs[offset];
			auto &entry = segment->entries[offset];
			if (fn(entry, regs, start))
			{
				break;
			}
		}
	}
	void scan(scanner fn) override
	{
		uint64_t count = 0;
		disassembler::disassembler d;
		for (T i=begin ; i!=end ; ++i)
		{
			debug_trace_entry e(*i, d);
			if (fn(e, count++))
			{
				return;
			}
		}
	}
	std::shared_ptr<trace_view> filter(filter_predicate fn) override
	{
		uint64_t idx = 0;
		index_map m;
		disassembler::disassembler d;
		for (T i=begin ; i!=end ; ++i)
		{
			debug_trace_entry e(*i, d);
			if (fn(e))
			{
				m.push_back(idx);
			}
			idx++;
		}
		return std::make_shared<concrete_traceview<T>>(std::enable_shared_from_this<concrete_streamtrace<T>>::shared_from_this(), std::move(m));
	}
	bool seek_to(uint64_t offset) override
	{
		if (!cache_segment(offset))
		{
			return false;
		}
		assert(segment_start != 0xffffffffffffffff);
		segment_offset = (offset - segment_start);
		return true;
	}
	virtual debug_trace_entry get_entry() override
	{
		assert(cache);
		assert(cache->entries.size() > segment_offset);
		return cache->entries[segment_offset];
	}
	virtual register_set get_regs() override
	{
		assert(cache);
		assert(cache->regs.size() > segment_offset);
		return cache->regs[segment_offset];
	}
};

/**
 * A `trace` subclass that refers to another trace.  This is the result of
 * calling `trace::filter()`.
 */
template<class T>
class concrete_traceview : public trace_view
{
	index_map indexes;
	std::shared_ptr<concrete_streamtrace<T>> t;
	public:
	/**
	 * Construct a new trace view from a concrete trace and a range of indexes
	 * in it.  This is used even when constructing a view from a view.
	 */
	concrete_traceview(decltype(t) tr, index_map &&i) : indexes(i), t(tr) {}
	uint64_t instruction_number_for_index(uint64_t idx) override
	{
		return indexes[idx];
	}
	uint64_t size() override
	{
		return indexes.size();
	}
	bool seek_to(uint64_t offset) override
	{
		return t->seek_to(indexes[offset]);
	}
	debug_trace_entry get_entry() override
	{
		return t->get_entry();
	}
	register_set get_regs() override
	{
		return t->get_regs();
	}
	void scan(scanner fn) override
	{
		scan(fn, 0, size()-1, forewards);
	}
	void scan(detailed_scanner fn, uint64_t start, uint64_t scan_end, int opts=0) override
	{
		int inc;
		if (!scan_range(start, scan_end, opts, inc, indexes.size()))
		{
			return;
		}
		uint64_t segstart = -1;
		std::unique_ptr<trace_segment> segment;
		for (; start<scan_end ; start+=inc)
		{
			auto i = indexes[start];
			if (segstart != (i / keyframe_interval))
			{
				segment = std::move(t->create_segment_for_index(i));
				segstart = (i / keyframe_interval);
			}
			uint64_t offset = i % keyframe_interval;
			auto &regs = segment->regs[offset];
			auto &entry = segment->entries[offset];
			if (fn(entry, regs, i))
			{
				break;
			}
		}
	}
	void scan(scanner fn, uint64_t start, uint64_t scan_end, int opts) override
	{
		int inc;
		uint64_t loop_end = scan_end;
		if (!scan_range(start, loop_end, opts, inc, indexes.size()))
		{
			return;
		}
		auto trace_iter = t->begin;
		auto begin = indexes.begin();
		disassembler::disassembler d;
		size_t last_index = 0;
		for (auto i=begin+start,e=begin+loop_end ; i!=e ; i+=inc)
		{
			trace_iter += (*i - last_index);
			last_index = *i;
			debug_trace_entry te(*trace_iter, d);
			if (fn(te, (*i)))
			{
				return;
			}
		}
	}
	std::shared_ptr<trace_view> filter(filter_predicate fn) override
	{
		auto trace_iter = t->begin;
		size_t last_index = 0;
		index_map m;
		disassembler::disassembler d;
		for (uint64_t idx : indexes)
		{
			trace_iter += (idx - last_index);
			last_index = idx;
			debug_trace_entry te(*trace_iter, d);
			if (fn(te))
			{
				m.push_back(idx);
			}
		}
		return std::make_shared<concrete_traceview<T>>(t, std::move(m));
	}
	std::shared_ptr<trace_view> inverted_view() override
	{
		return std::make_shared<concrete_traceview<T>>(t, indexes.inverted_map(t->size()));
	}
};

/**
 * Metadata describing v1 trace files.
 */
struct trace_v1_traits {
	/**
	 * v1 traces have no header
	 */
	__attribute__((unused)) // This is used, but only via template instantiation.
	static const int offset = 0;
	/**
	 * Format of the trace entries.
	 */
	typedef debug_trace_entry_disk_v1 format;
};
/**
 * Metadata describing v2 trace files.
 */
struct trace_v2_traits {
	/**
	 * v2 traces have one byte of version number then CheriStreamTrace as a
	 * string.
	 */
	static const int offset = sizeof(debug_trace_entry_disk);
	/**
	 * Format of the trace entries.
	 */
	typedef debug_trace_entry_disk format;
};
/**
 * Metadata describing v3 trace files.
 */
struct trace_v3_traits {
	/**
	 * v3 traces have one byte of version number then CheriTraceV03 as a
	 * string.
	 */
	static const int offset = sizeof(debug_trace_entry_disk_v3);
	/**
	 * Format of the trace entries.
	 */
	typedef debug_trace_entry_disk_v3 format;
};


/**
 * Abstract class implementing file reading.
 *
 * Subclasses of this read from either raw files or compressed files.
 *
 * All subclasses of this must be thread safe.  Any of the methods in this
 * class can be called from any thread.
 */
struct file : public fast_enumeration<uint8_t>
{
	/**
	 * Read part of the file.  This reads `length` bytes from offset `start` in
	 * the file, writing the result into `buffer`.  The return value is the
	 * number of bytes read.  This is guaranteed to be `length` for any
	 * in-bounds reads.
	 */
	virtual size_t read(void *buffer, off_t start, size_t length) = 0;
	/**
	 * Virtual destructor, allowing cleanup in subclasses.
	 */
	virtual ~file() {}
	/**
	 * Returns the logical size of the file (for compressed files, this returns
	 * the size of the uncompressed file.
	 */
	virtual size_t size() = 0;
	/**
	 * Opens a named file.  This will automatically detect if the file is
	 * xz-compressed.
	 */
	static std::shared_ptr<file> open(const std::string &file);
	bool enumerate(enumerator &e, size_t start) override
	{
		// For testing, provide an implementation of enumerate that will never
		// return a complete dist trace entry.
#ifdef EVIL_FILE
		size_t bytes = read(e.buffer, start, 25);
#else
		size_t bytes = read(e.buffer, start, enumerator::internal_buffer_size);
#endif
		e.ptr = e.buffer;
		e.size = bytes;
		e.shared_buffer = nullptr;
		return bytes > 0;
	}
};

/**
 * Class encapsulating an uncompressed file.
 */
class plain_file : public file
{
	friend class mmap_file;
	/**
	 * File descriptor for this file.
	 */
	int fd;
	/**
	 * Size of the file.  This is assumed not to change as long as this object
	 * exists.
	 */
	size_t file_size;
	size_t read(void *buffer, off_t start, size_t length) override
	{
		// Give up if this is out of bounds.
		if ((start < 0) || ((size_t)start > file_size))
		{
			return 0;
		}
		// If we're trying to read past the end, read a bit less
		if (start + length > file_size)
		{
			length = file_size - start;
		}
		size_t total = 0;
		do
		{
			auto ret = pread(fd, buffer, length, start);
			// EOF, return whatever we have.  This shouldn't be hit, but might
			// be if someone truncates the buffer.  Also give up in the event
			// of an error.
			if (ret < 0)
			{
				break;
			}
			length -= ret;
			total += ret;
			start += ret;
			buffer = (void*)((char*)buffer + ret);
		} while (length > 0);
		return total;
	}
	size_t size() override
	{
		return file_size;
	}
	public:
	/**
	 * Construct a file from a specified file descriptor.
	 */
	plain_file(int filedesc) : fd(filedesc)
	{
		assert(filedesc >= 0);
		// Find the size of the file
		file_size = lseek(filedesc, 0, SEEK_END);
	}
	/**
	 * Open a file and return a shared pointer to an object encapsulating it.
	 * Returns `nullptr` if opening the file fails.
	 */
	static std::shared_ptr<plain_file> open(const std::string &file_name)
	{
		int fd = ::open(file_name.c_str(), O_RDONLY);
		if (fd < 0)
		{
			return nullptr;
		}
		return std::make_shared<plain_file>(fd);
	}
	/**
	 * Close the file descriptor on destruction.
	 */
	~plain_file() override
	{
		close(fd);
	}
};

/**
 * Memory mapped file.
 */
class mmap_file : public file
{
	/**
	 * The underlying file.
	 */
	std::shared_ptr<plain_file> file;
	/**
	 * The place where this file is mapped in the address space.
	 */
	uint8_t *mapped;
	size_t size() override
	{
		return file->size();
	}
	size_t read(void *buffer, off_t start, size_t length) override
	{
		length = std::min(length, file->size() - (size_t)start);
		memcpy(buffer, mapped+start, length);
		return length;
	}
	bool enumerate(enumerator &e, size_t start) override
	{
		size_t sz = file->size();
		if (start > sz)
		{
			return false;
		}
		e.ptr = mapped + start;
		e.size = sz - start;
		e.shared_buffer = nullptr;
		return true;
	}
	public:
	/**
	 * Create a memory mapped file.
	 */
	mmap_file(std::shared_ptr<plain_file> &f, void *m) :
		file(f), mapped((uint8_t*)m)
	{
		madvise(mapped, file->size(), MADV_WILLNEED);
	}
	/**
	 * Destructor, unmap the file.
	 */
	~mmap_file()
	{
		munmap(mapped, file->size());
	}
	static std::shared_ptr<mmap_file> open(std::shared_ptr<plain_file> f)
	{
		void *mapped = mmap(nullptr, f->size(), PROT_READ, MAP_PRIVATE, f->fd, 0);
		if (mapped == MAP_FAILED)
		{
			return nullptr;
		}
		return std::make_shared<mmap_file>(f, mapped);
	}
};

/**
 * Class encapsulating an xz-compressed file.  This allows code to be agnostic
 * as to whether it is reading from a compressed or uncompressed file.
 */
class xz_file : public file
{
	/**
	 * A block in the compressed file, constructed from the index.
	 */
	struct compressed_block
	{
		/**
		 * Offset of the start of the block in the compressed file.
		 */
		off_t compressed_start;
		/**
		 * Size of the block in the compressed file.
		 */
		size_t compressed_size;
		/**
		 * Offset of the start of the block as it would appear in the
		 * uncompressed file.
		 */
		off_t uncompressed_start;
		/**
		 * Size of the block as it would appear in the uncompressed file.
		 */
		size_t uncompressed_size;
		/**
		 * Equality test.  Two blocks are equal if and only if all fields are
		 * equal.
		 */
		bool operator==(const compressed_block &b)
		{
			return (compressed_start == b.compressed_start) &&
			       (compressed_size == b.compressed_size) &&
			       (uncompressed_start == b.uncompressed_start) &&
			       (uncompressed_size == b.uncompressed_size);
		}
	};
	/**
	 * A structure to manage a cached (decompressed) block of data.
	 */
	struct cached_block
	{
		/**
		 * The origin of this block.
		 */
		compressed_block metadata = {0,0,0,0};
		/**
		 * The decompressed data.
		 */
		std::shared_ptr<uint8_t> data;
	};
	/**
	 * A single (currently) cached block.
	 */
	cached_block cache;
	/**
	 * A lock protecting the cache.
	 */
	std::mutex cache_lock;
	/**
	 * Index of blocks within this file.
	 */
	std::vector<compressed_block> offsets;
	/**
	 * The file descriptor corresponding to this file.
	 */
	std::shared_ptr<file> compressed_file;
	/**
	 * The size of the uncompressed file.
	 */
	size_t uncompressed_size = 0;
	/**
	 * Flags for the stream.  We assume that there is a single stream in the
	 * file.
	 */
	lzma_stream_flags stream_flags;
	bool enumerate(enumerator &e, size_t start) override
	{
		// If the requested index is not within the existing buffer, load a new
		// one.
		if ((e.ptr == nullptr) ||
			(e.state[0] >= start) ||
			(e.state[0] + e.state[1] <= start))
		{
			int block_idx = block_for_offset(start);
			if (block_idx < 0)
			{
				return false;
			}
			compressed_block &b = offsets[block_idx];
			e.shared_buffer = read_block(b);
			e.state[0] = b.uncompressed_start;
			e.state[1] = b.uncompressed_size;
		}
		size_t offset = start - e.state[0];
		e.ptr = e.shared_buffer.get();
		e.size = e.state[1] - offset;
		e.ptr += offset;
		return true;
	}
	public:
	/**
	 * Create an `xz_file` object.  Callers are responsible for ensuring that
	 * the file represented by `f` really is an xz file.  The `flags` parameter
	 * is the stream flags read from the file.
	 */
	xz_file(std::shared_ptr<file> f, lzma_stream_flags flags) : compressed_file(f),
		stream_flags(flags)
	{
		// Read the index into a temporary buffer
		std::unique_ptr<uint8_t> index_buffer(new uint8_t[stream_flags.backward_size]);
		compressed_file->read((void*)index_buffer.get(),
		                      compressed_file->size() - stream_flags.backward_size - 12,
		                      stream_flags.backward_size);
		lzma_index *idx;
		uint64_t mem = UINT64_MAX;
		size_t pos = 0;
		lzma_ret ret = lzma_index_buffer_decode(&idx, &mem, nullptr,
				index_buffer.get(), &pos, stream_flags.backward_size);
		if (ret != LZMA_OK)
		{
			compressed_file = nullptr;
			return;
		}
		lzma_index_iter iter;
		lzma_index_iter_init(&iter, idx);
		// Collect the block indexes
		while (!lzma_index_iter_next(&iter, LZMA_INDEX_ITER_ANY))
		{
			struct compressed_block block;
			block.compressed_start = iter.block.compressed_file_offset;
			block.compressed_size = iter.block.total_size;
			block.uncompressed_start = iter.block.uncompressed_file_offset;
			block.uncompressed_size = iter.block.uncompressed_size;
			offsets.push_back(block);
		}
		lzma_index_end(idx, nullptr);
		assert(offsets.size() > 0);
		compressed_block &b = offsets.back();
		// The size of the uncompressed file is the end of the last block.
		uncompressed_size = b.uncompressed_start + b.uncompressed_size;
		// We're probably going to want to start reading the file at the start,
		// so kick off an async load of the first block.
		std::async(std::launch::async, [&]() {
			read_block(offsets[0]);
		});
	}
	size_t size() override
	{
		return uncompressed_size;
	}
	size_t read(void *buffer, off_t start, size_t length) override
	{
		int block_idx = block_for_offset(start);
		if (block_idx < 0)
		{
			return 0;
		}
		size_t copied = 0;
		while (length > 0)
		{
			if (block_idx >= (int)offsets.size())
			{
				break;
			}
			auto &b = offsets[block_idx++];
			auto data = read_block(b);
			size_t copy_start = start - b.uncompressed_start;
			size_t copy_length = b.uncompressed_size - copy_start;
			copy_length = std::min(copy_length, length);
			memcpy(buffer, data.get()+copy_start, copy_length);
			copied += copy_length;
			start += copy_length;
			length -= copy_length;
			buffer = (void*)((char*)buffer + copy_length);
		}
		return copied;
	}
	public:
	/**
	 * Returns the index of the block that corresponds to a particular offset,
	 * or -1 if no block matches.
	 */
	int block_for_offset(off_t off)
	{
		auto cmp = [=](const compressed_block &a) {
			return (a.uncompressed_start <= off) && ((a.uncompressed_start +
						a.uncompressed_size) > (size_t)off);
		};
		auto it = std::find_if(offsets.begin(), offsets.end(), cmp);
		if (it == offsets.end())
		{
			return -1;
		}
		return it - offsets.begin();
	}
	/**
	 * Reads a block into a new allocation.
	 */
	std::shared_ptr<uint8_t> read_block(compressed_block b)
	{
		{
			std::lock_guard<std::mutex> lock(cache_lock);
			if (b == cache.metadata)
			{
				return cache.data;
			}
		}
		std::unique_ptr<uint8_t> input_buffer(new uint8_t[b.compressed_size]);
		compressed_file->read((void*)input_buffer.get(), b.compressed_start, b.compressed_size);
		lzma_block block;
		lzma_filter filters[LZMA_FILTERS_MAX + 1];
		filters[0].id = LZMA_VLI_UNKNOWN;
		block.filters = filters;
		block.version = 1;
		block.check = stream_flags.check;
		block.header_size = lzma_block_header_size_decode(*input_buffer);
		lzma_ret ret = lzma_block_header_decode(&block, nullptr, input_buffer.get());
		if (ret != LZMA_OK)
		{
			return nullptr;
		}
		std::shared_ptr<uint8_t> output_buffer(new uint8_t[b.uncompressed_size]);
		size_t in_pos = block.header_size;
		size_t out_pos = 0;
		ret = lzma_block_buffer_decode(&block, nullptr, input_buffer.get(),
				&in_pos, b.compressed_size, output_buffer.get(), &out_pos,
				b.uncompressed_size);
		if (ret != LZMA_OK)
		{
			return nullptr;
		}
		{
			std::lock_guard<std::mutex> lock(cache_lock);
			cache.metadata = b;
			cache.data = output_buffer;
		}
		return output_buffer;
	}
	/**
	 * Open a file.  This returns `nullptr` if the underlying file does not
	 * appear to be xz-encoded.
	 */
	static std::shared_ptr<xz_file> open(std::shared_ptr<file> f)
	{
		uint8_t buffer[12];
		f->read((void*)buffer, f->size()-12, 12);
		lzma_stream_flags stream_flags;
		lzma_ret ret = lzma_stream_footer_decode(&stream_flags, buffer);
		if (ret != LZMA_OK)
		{
			return nullptr;
		}
		return std::make_shared<xz_file>(f, stream_flags);
	}
};

std::shared_ptr<file> file::open(const std::string &file)
{
	auto raw = plain_file::open(file);
	if (!raw)
	{
		return nullptr;
	}
	std::shared_ptr<struct file> mmapped(mmap_file::open(raw));
	if (!mmapped)
	{
		mmapped = raw;
	}
	auto xz = xz_file::open(mmapped);
	return xz ? xz : mmapped;
}

/**
 * File stream.  Within iterators, we use a shared pointer to an input file
 * stream for reading.
 */
typedef std::shared_ptr<file> filestream;


/**
 * Iterator for accessing elements in a streamtrace.  This is a template to
 * allow it to be used for both v1 and v2 streamtraces.  The differences
 * between the two formats are provided by the `trace_v?_traits` classes.
 */
template<class Traits>
class streamtrace_iterator : public std::iterator<std::random_access_iterator_tag, typename Traits::format, uint64_t>
{
	static const size_t entry_size = sizeof(typename Traits::format);
	/**
	 * The type of this iterator.
	 */
	typedef streamtrace_iterator<Traits> iter;
	/**
	 * Offset within the file of this of this iterator.
	 */
	uint64_t offset = 0;
	/**
	 * The file that this iterator refers to.
	 */
	filestream file;
	/**
	 */
	mutable file::enumerator e;
	/**
	 * The start of the buffer.
	 */
	mutable uint64_t buffer_start = -1;
	__attribute__((noinline))
	typename Traits::format get_slow() const {
		// If we're completely out of range, load the start.  Also do this
		// if the start is not in range, so that we can always read
		// forwards, which simplifies the logic here considerably (at the
		// expense of a small number of redundant reads).
		if ((buffer_start == (uint64_t)-1) ||
			((offset + entry_size) < buffer_start) ||
			(offset >= buffer_start + e.size))
		{
			file->enumerate(e, offset);
			buffer_start = offset;
		}
		if ((offset < buffer_start) ||
		    ((buffer_start + e.size) < offset+entry_size))
		{
			// The place we're going to start loading from.  If our block
			// boundaries are aligned, then this is the same as the offset
			size_t load_start = offset;
			// Small buffer where we'll copy the bytes for an unaligned value.
			uint8_t little_buffer[entry_size];
			// The number of bytes that we're unable to load from the start.
			ptrdiff_t off_by_bytes = 0;
			if ((offset >= buffer_start) && ((offset + entry_size) > buffer_start + e.size))
			{
				size_t start = offset - buffer_start;
				off_by_bytes = e.size - start;
				if (off_by_bytes != 0)
				{
					assert(off_by_bytes < (ptrdiff_t)entry_size);
					assert(off_by_bytes > 0);
					// Copy the first bytes from the end
					memcpy(little_buffer, e.ptr + start, off_by_bytes);
					load_start += off_by_bytes;
				}
			}
			bool loaded = file->enumerate(e, load_start);
			if (!loaded)
			{
				buffer_start = -1;
				return typename Traits::format();
			}
			buffer_start = load_start;
			if ((off_by_bytes > 0) || (e.size - (load_start - offset) < entry_size))
			{
				size_t insert_offset = off_by_bytes;
				while (insert_offset < entry_size)
				{
					size_t bytes_to_copy = std::min(e.size, entry_size - insert_offset);
					memcpy(little_buffer + insert_offset, e.ptr, bytes_to_copy);
					insert_offset += bytes_to_copy;
					if (insert_offset == entry_size)
					{
						return *reinterpret_cast<typename Traits::format*>(little_buffer);
					}
					assert(off_by_bytes > 0);
					buffer_start += bytes_to_copy;
					file->enumerate(e, buffer_start);
				}
				assert(0);
			}
			assert(offset - buffer_start + entry_size <= e.size);
		}
		assert(offset - buffer_start + entry_size <= e.size);
		return *reinterpret_cast<typename Traits::format*>(e.ptr + offset - buffer_start);
	}
	public:
	/**
	 * Constructs an iterator from a file at a specific offset.
	 */
	streamtrace_iterator(filestream f, uint64_t o) : offset(o), file(f) {}
	/**
	 * Copy constructor.
	 */
	streamtrace_iterator(streamtrace_iterator &other) :
		streamtrace_iterator(other.file, other.offset) {}
	/**
	 * Move constructor.
	 */
	streamtrace_iterator(streamtrace_iterator &&other) :
		streamtrace_iterator(std::move(other.file), other.offset) {}
	/**
	 * Construct a new iterator referring to the same file with a new offset.
	 */
	iter operator+(int x) {
		iter copy(file, offset + sizeof(typename Traits::format) * x);
		return copy;
	}
	/**
	 * Construct a new iterator referring to the same file with a new offset.
	 */
	iter operator++(int x) {
		iter copy(file, offset + sizeof(typename Traits::format) * x);
		return copy;
	}
	/**
	 * Move the offset within the file forwards.
	 */
	iter &operator++() {
		offset += sizeof(typename Traits::format) * 1;
		return *this;
	}
	/**
	 * Move the offset within the file forwards.
	 */
	iter &operator+=(int x) {
		offset += x * sizeof(typename Traits::format);
		return *this;
	}
	/**
	 * Returns the difference between two iterators to the same file.
	 * Undefined behaviour if called with iterators to different files.
	 */
	uint64_t operator-(const streamtrace_iterator<Traits>& other) {
		assert(file == other.file);
		return (offset - other.offset) / sizeof(typename Traits::format);
	}
	/**
	 * Return a copy of the trace entry at the current file offset.
	 */
	__attribute__((always_inline))
	inline typename Traits::format operator*() const {
		if (expect((offset < buffer_start) ||
		           ((buffer_start + e.size) <= offset+entry_size), 0))
		{
			return get_slow();
		}
		return *reinterpret_cast<typename Traits::format*>(e.ptr + offset - buffer_start);
	}
	/**
	 * Compares two iterators.  Undefined if they point to different files.
	 */
	bool operator!=(streamtrace_iterator<Traits> &o)
	{
		assert(file == o.file);
		return offset != o.offset;
	}
};

/**
 * Helper template for constructing the streamtrace.
 */
template<class T> inline
std::shared_ptr<concrete_streamtrace<streamtrace_iterator<T>>>
make_trace(filestream &file, off_t size, trace::notifier fn)
{
	typedef streamtrace_iterator<T> iter;
	iter begin(file, T::offset);
	// If we have a portion at the end of a trace, then ignore it.
	size -= (size - T::offset) % sizeof(typename T::format);
	assert((size - T::offset) % sizeof(typename T::format) == 0);
	iter end(file, size);
	return std::make_shared<concrete_streamtrace<iter>>(std::move(begin), std::move(end), fn);
}


/**
 * Extract bits in an unsigned integer value between the range high and low
 * (inclusive).
 */
template<int high, int low=high, typename T>
typename std::enable_if<std::is_unsigned<T>::value, T>::type extract_bits(T val)
{
	T mask = std::numeric_limits<T>::max();
	mask >>= (sizeof(T)*8) - high - 1;
	return (val >> low) & mask;
}

/**
 * Expand a compressed address that appears in a CHERI streamtrace.
 */
uint64_t expand_address(uint32_t shrt)
{
	// Taken from berictl.c
	uint64_t addr = 0;
	uint64_t cmp = (uint64_t) shrt;
	// Move 4 bits of the segment up to the top.
	addr |= (cmp & 0xF0000000)<<31;
	// If the address segment was non-zero, set the top bit also.
	if (addr != 0) addr |= 0x8000000000000000;
	// Shift up the top bits of the 40-bit virtual address
	addr |= (cmp & 0x0FF00000)<<12;
	if (addr & 0x8000000000) addr |= 0x07FFFF0000000000;
	// Or in the bottom 20 bits of the 40-bit virtual address.
	addr |= (cmp & 0x000FFFFF);
	// (There will be 12 zeroed bits in the middle where address information is
	// missing)
	return addr;
}

/**
 * Decode a capability register from streamtrace values.  `val2` is always
 * `val2` from the streamtrace, but `val1` is either `val1` or `pc` depending
 * on the trace format.
 */
void decode_cap(capability_register &cap, uint64_t val2, uint64_t val1)
{
	cap.valid = extract_bits<63>(val2);
	cap.unsealed = extract_bits<62>(val2);
	cap.permissions = extract_bits<61,54>(val2);
	cap.type = extract_bits<53,32>(val2);
	cap.offset = expand_address(extract_bits<31,0>(val2));
	cap.base = expand_address(extract_bits<63,32>(val1));
	cap.length = expand_address(extract_bits<31,0>(val1));
}
/**
 * Decode a capability register from streamtrace (V3) values.
 * Caps: val2 = (tag << 63) | (otype << 32) | (perms << 1) | s << 0,
 *  val3 = cursor, val4 = base, val5 = length
 */
void decode_cap(capability_register &cap, uint64_t val2, uint64_t val3,
		uint64_t val4, uint64_t val5)
{
	cap.valid = extract_bits<63>(val2);
	/*
	 * XXXAM: the meaning of this is not clear
	 * why are we interpreting bit 0 as unsealed instead of sealed?
	 *
	 * Qemu stores is_cap_sealed(cap) ? 1 : 0 (capability sealed flag).
	 * The bluespec implementation stores the capability sealed flag.
	 */
	cap.unsealed = extract_bits<0>(val2);
	cap.permissions = extract_bits<31,1>(val2);
	cap.type = extract_bits<55,32>(val2);
	cap.base = val4;
	cap.length = val5;
	cap.offset = val3 - cap.base;
}


/**
 * Decode a trace entry given the fields from the on-disk version that have
 * variable meanings.
 */
void decode_entry(debug_trace_entry &e, uint8_t version, uint64_t val1, uint64_t val2)
{
	val1 = cheri_byte_order_to_host(val1);
	val2 = cheri_byte_order_to_host(val2);
	switch (version)
	{
		default:
			break;
		case 1:
		{
			e.reg_value.gp = val2;
			break;
		}
		case 2:
		{
			e.is_load = true;
			e.reg_value.gp = val2;
			e.memory_address = val1;
			break;
		}
		case 3:
		{
			e.is_store = true;
			e.reg_value.gp = val2;
			e.memory_address = val1;
			break;
		}
		case 11:
		{
			decode_cap(e.reg_value.cap, val2, val1);
			break;
		}
		case 12:
		{
			e.is_load = true;
			e.memory_address = val1;
			decode_cap(e.reg_value.cap, val2, e.pc);
			e.pc = 0;
			break;
		}
		case 13:
		{
			e.is_store = true;
			decode_cap(e.reg_value.cap, val2, e.pc);
			e.memory_address = val1;
			e.pc = 0;
			break;
		}
	}
}

/**
 * Decode a trace entry given the fields from the on-disk version that have
 * variable meanings.
 */
void decode_entry(debug_trace_entry &e, uint8_t version, uint64_t val1,
        uint64_t val2, uint64_t val3, uint64_t val4, uint64_t val5)
{
	val1 = cheri_byte_order_to_host(val1);
	val2 = cheri_byte_order_to_host(val2);
	val3 = cheri_byte_order_to_host(val3);
	val4 = cheri_byte_order_to_host(val4);
	val5 = cheri_byte_order_to_host(val5);
	switch (version)
	{
		default:
			break;
		case 1:
		{
			e.reg_value.gp = val2;
			break;
		}
		case 2:
		{
			e.is_load = true;
			e.reg_value.gp = val2;
			e.memory_address = val1;
			break;
		}
		case 3:
		{
			e.is_store = true;
			e.reg_value.gp = val2;
			e.memory_address = val1;
			break;
		}
		case 11:
		{
			decode_cap(e.reg_value.cap, val2, val3, val4, val5);
			break;
		}
		case 12:
		{
			e.is_load = true;
			e.memory_address = val1;
			decode_cap(e.reg_value.cap, val2, val3, val4, val5);
			break;
		}
		case 13:
		{
			e.is_store = true;
			decode_cap(e.reg_value.cap, val2, val3, val4, val5);
			e.memory_address = val1;
			break;
		}
	}
}

} // Anonymous namespace

	/**
	 * Constructs an in-memory trace entry from the v2 on-disk format.
	 */
debug_trace_entry::debug_trace_entry(const debug_trace_entry_disk &d,
		disassembler::disassembler &dis) :
	pc(cheri_byte_order_to_host(d.pc)),
	cycles(cheri_byte_order_to_host(d.cycles)),
	memory_address(0),
	inst(cheri_byte_order_to_host(d.inst)),
	thread(cheri_byte_order_to_host(d.thread)),
	asid(cheri_byte_order_to_host(d.asid)),
	exception(cheri_byte_order_to_host(d.exception)),
	is_load(0),
	is_store(0),
	reg_num((d.version == 4) ? 100 : dis.disassemble(inst).destination_register)
{
	if (d.version != 4)
	{
		assert(reg_num == (uint8_t)dis.disassemble(inst).destination_register);
	}
	decode_entry(*this, d.version, d.val1, d.val2);
}
	/**
	 * Constructs an in-memory trace entry from the v3 on-disk format.
	 */
debug_trace_entry::debug_trace_entry(const debug_trace_entry_disk_v3 &d,
		disassembler::disassembler &dis) :
	pc(cheri_byte_order_to_host(d.pc)),
	cycles(cheri_byte_order_to_host(d.cycles)),
	memory_address(0),
	inst(cheri_byte_order_to_host(d.inst)),
	thread(cheri_byte_order_to_host(d.thread)),
	asid(cheri_byte_order_to_host(d.asid)),
	exception(cheri_byte_order_to_host(d.exception)),
	is_load(0),
	is_store(0),
	reg_num((d.version == 4) ? 100 : dis.disassemble(inst).destination_register)
{
	if (d.version != 4)
	{
		assert(reg_num == (uint8_t)dis.disassemble(inst).destination_register);
	}
	decode_entry(*this, d.version, d.val1, d.val2, d.val3, d.val4, d.val5);
}
/**
 * Constructs an in-memory trace entry from the v1 on-disk format.
 */
debug_trace_entry::debug_trace_entry(const debug_trace_entry_disk_v1 &d,
		disassembler::disassembler &dis) :
	pc(cheri_byte_order_to_host(d.pc)),
	cycles(cheri_byte_order_to_host(d.cycles)),
	inst(cheri_byte_order_to_host(d.inst)),
	thread(0),
	asid(0),
	exception(cheri_byte_order_to_host(d.exception)),
	is_load(0),
	is_store(0),
	reg_num((d.version == 4) ? 100 : dis.disassemble(inst).destination_register)
{
	decode_entry(*this, d.version, d.val1, d.val2);
}

void keyframe::update(const debug_trace_entry &e, disassembler::disassembler &dis)
{
	cycles += (e.cycles - cycle_counter) % 1024;
	cycle_counter = e.cycles;
	if (e.gpr_number() > 0)
	{
		int gpr = e.gpr_number();
		regs.gpr[gpr-1] = e.reg_value.gp;
		regs.valid_gprs[gpr-1] = true;
	}
	if (e.capreg_number() >= 0)
	{
		int capr = e.capreg_number();
		regs.cap_reg[capr] = e.reg_value.cap;
		regs.valid_caps[capr] = true;
	}
	// If the trace entry doesn't have a PC, then assume that it's not a
	// branch or exception target and that it follows the last one.
	if (e.pc != 0)
	{
		pc = e.pc;
	}
	else
	{
		pc = pc + 4;
	}
}

std::shared_ptr<trace> trace::open(const std::string &file_name, notifier fn)
{
	std::shared_ptr<trace> ret;
	auto file = file::open(file_name);
	if (!file)
	{
		return nullptr;
	}
	auto size = file->size();
	char buffer[trace_v3_traits::offset + 1];
	buffer[trace_v3_traits::offset] = 0;
	file->read((void*)&buffer, 0, trace_v3_traits::offset);
	std::string header(buffer+1, sizeof("CheriStreamTrace"));
	if (strcmp(header.c_str(), "CheriTraceV03") == 0)
	{
		if (buffer[0] - (char) 0x80 != (char) 3)
		{
			return nullptr;
		}
		ret = make_trace<trace_v3_traits>(file, size, fn);
	}
	else if (strcmp(header.c_str(), "CheriStreamTrace") != 0)
	{
		ret = make_trace<trace_v1_traits>(file, size, fn);
	}
	else
	{
		if (buffer[0] - (char) 0x80 != (char) 2)
		{
			return nullptr;
		}
		ret = make_trace<trace_v2_traits>(file, size, fn);
	}
	return ret;
}
std::shared_ptr<trace> trace::open(const std::string &file_name)
{
	notifier fn = nullptr;
	return trace::open(file_name, fn);
}
void trace_segment::add_entry(disassembler::disassembler &d,
                              keyframe &kf,
                              const debug_trace_entry &entry)
{
	uint64_t old_cycles = kf.cycles;
	kf.update(entry, d);
	entries.push_back(entry);
	regs.push_back(kf.regs);
	debug_trace_entry &e = entries.back();
	if (e.pc == 0)
	{
		e.pc = kf.pc;
	}
	e.cycles = kf.cycles;
	e.dead_cycles = kf.cycles - old_cycles;
	// Don't generate negative dead cycle numbers if we've somehow ended up with
	// two trace entries on the same cycle count (no idea why this happens, but
	// it does in some traces).
	if (e.dead_cycles > 0)
	{
		e.dead_cycles--;
	}
}

