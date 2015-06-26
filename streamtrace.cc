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
#include <atomic>
#include <condition_variable>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>


using namespace cheri;
using namespace streamtrace;

trace::~trace() {}

namespace {

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
			debug_trace_entry entry(*begin);
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
 * Number of entries between keyframes.
 */
const uint64_t keyframe_interval = 1<<16;
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
			kf.update(*i, d);
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
		segment_start = offset / keyframe_interval;
		uint64_t length = std::min(keyframe_interval, (end - begin) - segment_start);
		T segment_begin = begin + segment_start;
		T segment_end = segment_begin + length + 1;
		return std::unique_ptr<trace_segment>(new trace_segment(disass, kf,
		                   std::move(segment_begin), std::move(segment_end)));
	}
	bool cache_segment(uint64_t offset)
	{
		if (offset / keyframe_interval == segment_start)
		{
			return true;
		}
		if (offset > end-begin)
		{
			return false;
		}
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
		if (!scan_range(start, scan_end, opts, inc, end-begin))
		{
			return;
		}
		for (T i=begin+start,e=begin+scan_end ; i!=e ; i+=inc)
		{
			debug_trace_entry te = *i;
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
	void scan(scanner fn)
	{
		uint64_t count = 0;
		for (T i=begin ; i!=end ; ++i)
		{
			debug_trace_entry e = *i;
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
		for (T i=begin ; i!=end ; ++i)
		{
			debug_trace_entry e = *i;
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
	void scan(scanner fn, uint64_t start, uint64_t scan_end, int opts)
	{
		int inc;
		uint64_t loop_end = scan_end;
		if (!scan_range(start, loop_end, opts, inc, indexes.size()))
		{
			return;
		}
		auto trace_iter = t->begin;
		auto begin = indexes.begin();
		for (auto i=begin+start,e=begin+loop_end ; i!=e ; i+=inc)
		{
			// FIXME: This does a lot of redundant iterator creation
			if (fn(*(trace_iter+(*i)), (*i)))
			{
				return;
			}
		}
	}
	std::shared_ptr<trace_view> filter(filter_predicate fn) override
	{
		auto i = t->begin;
		index_map m;
		for (uint64_t idx : indexes)
		{
			// FIXME: This does a lot of redundant iterator creation
			if (fn(*(i+idx)))
			{
				m.push_back(idx);
			}
		}
		return std::make_shared<concrete_traceview<T>>(t, std::move(m));
	}
	std::shared_ptr<trace_view> inverted_view()
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
 * Simple wrapper around a file descriptor.  Exists so that it can be reference
 * counted by shared_ptr and close the file once it is no longer needed.  This
 * exists because iterators want to have a stateless reference to a file.
 */
struct fd
{
	/**
	 * UNIX file descriptor.  Defaults to invalid value.
	 */
	int fileno = -1;
	/**
	 * Construct the `fd` from a file descriptor.
	 */
	fd(int f) : fileno(f) {}
	/**
	 * Close the file descriptor when this is destroyed.
	 */
	~fd() { close(fileno); }
};

/**
 * File stream.  Within iterators, we use a shared pointer to an input file
 * stream for reading.
 */
typedef std::shared_ptr<fd> filestream;


/**
 * Iterator for accessing elements in a streamtrace.  This is a template to
 * allow it to be used for both v1 and v2 streamtraces.  The differences
 * between the two formats are provided by the `trace_v?_traits` classes.
 */
template<class Traits>
class streamtrace_iterator : public std::iterator<std::random_access_iterator_tag, typename Traits::format, uint64_t> {
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
	public:
	/**
	 * Constructs an iterator from a file at a specific offset.
	 */
	streamtrace_iterator(filestream f, int o) : offset(o), file(f) {}
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
	typename Traits::format operator*() const {
		typename Traits::format buffer;
		pread(file->fileno, (void*)&buffer, sizeof(buffer), offset);
		return buffer;
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
	iter end(file, size);
	return std::make_shared<concrete_streamtrace<iter>>(std::move(begin), std::move(end), fn);
}

} // Anonymous namespace

void keyframe::update(const debug_trace_entry &e, disassembler::disassembler &dis)
{
	cycles += (e.cycles - cycle_counter) % 1024;
	cycle_counter = e.cycles;
	if ((e.version == 1) || e.version == 2)
	{
		int reg_no = dis.disassemble(e.inst).destination_register;
		if ((reg_no > 0) && (reg_no < 32))
		{
			regs.gpr[reg_no-1] = e.val2;
			regs.valid_gprs[reg_no-1] = true;
		}
	}
	// If the trace entry doesn't have a PC, then assume that it's not a
	// branch or exception target and that it follows the last one.
	if (e.pc != 0)
	{
		pc = e.pc;
	}
	else
	{
		pc = e.pc + 4;
	}
}

std::shared_ptr<trace> trace::open(const std::string &file_name, notifier fn)
{
	std::shared_ptr<trace> ret;
	int fileno = ::open(file_name.c_str(), O_RDONLY);
	if (fileno < 0)
	{
		return std::shared_ptr<trace>(nullptr);
	}
	auto file = std::make_shared<fd>(fileno);
	auto size = lseek(fileno, 0, SEEK_END);
	char buffer[trace_v2_traits::offset + 1];
	buffer[trace_v2_traits::offset] = 0;
	lseek(fileno, 0, SEEK_SET);
	pread(fileno, (void*)&buffer, trace_v2_traits::offset, 0);
	std::string header(buffer+1, sizeof("CheriStreamTrace"));
	if (strcmp(header.c_str(), "CheriStreamTrace") != 0)
	{
		ret = make_trace<trace_v1_traits>(file, size, fn);
	}
	else
	{
		if (buffer[0] - (char) 0x80 != (char) 2)
		{
			throw std::invalid_argument("Unrecognised trace file version");
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

