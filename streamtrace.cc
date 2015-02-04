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
#include <fstream>
#include <thread>

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
 * Concrete subclass of the streamtrace.  Manages trace segments.
 */
template<class T>
class concrete_streamtrace : public trace
{
	/**
	 * Number of entries between keyframes.
	 */
	const uint64_t keyframe_interval = 1<<16;
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
	 * Scans the entire streamtrace and records keyframes for faster seeking.
	 *
	 * This method is expected to be invoked precisely once, from another
	 * thread.
	 */
	void preload()
	{
		assert(!finished_loading);
		keyframe kf;
		keyframes.push_back(kf);
		disassembler::disassembler d;
		int frame = keyframe_interval;
		for (T i=begin ; i!=end ; ++i)
		{
			if (cancel)
			{
				return;
			}
			kf.update(*i, d);
			if (frame-- == 0)
			{
				frame = keyframe_interval;
				std::lock_guard<std::mutex> lock(keyframe_lock);
				keyframes.push_back(kf);
				notify.notify_all();
			}
		}
		finished_loading = true;
		notify.notify_all();
	}
	/**
	 * Returns the keyframe associated with a specific offset.  This is
	 * thread-safe with respect to a thread running the `preload()` method.  It
	 * will block until preloading is finished.
	 */
	keyframe get_keyframe(uint64_t &offset)
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
	bool load_segment(uint64_t offset)
	{
		if (offset / keyframe_interval == segment_start)
		{
			return true;
		}
		if (offset > end-begin)
		{
			return false;
		}
		auto kf = get_keyframe(offset);
		segment_start = offset / keyframe_interval;
		uint64_t length = std::min(keyframe_interval, (end - begin) - segment_start);
		T segment_begin = begin + segment_start;
		T segment_end = segment_begin + length;
		cache.reset(new trace_segment(disass, kf, std::move(segment_begin), std::move(segment_end)));
		return true;
	}
	public:
	/**
	 * Construct a streamtrace from two iterators.  
	 */
	concrete_streamtrace(T &&b, T &&e) : begin(b), end(e)
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
	bool seek_to(uint64_t offset) override
	{
		if (!load_segment(offset))
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
	static const int offset = 17; // length of %cCheriStreamTrace;
	/**
	 * Format of the trace entries.
	 */
	typedef debug_trace_entry_disk_v1 format;
};

/**
 * File stream.  Within iterators, we use a shared pointer to an input file
 * stream for reading.
 */
typedef std::shared_ptr<std::ifstream> filestream;
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
	typename Traits::format operator*() {
		file->seekg(offset);
		typename Traits::format buffer;
		file->read((char*)&buffer, sizeof(buffer));
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
make_trace(filestream &file, off_t size)
{
	typedef streamtrace_iterator<T> iter;
	iter begin(file, T::offset);
	iter end(file, size);
	return std::make_shared<concrete_streamtrace<iter>>(std::move(begin), std::move(end));
}

} // Anonymous namespace

void keyframe::update(const debug_trace_entry &e, disassembler::disassembler &dis)
{
	cycles += (e.cycles - cycle_counter) % 512 + 512;
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
	// If the trace entry doesn't have a PC, it's because 
	if (e.pc != 0)
	{
		pc = e.pc;
	}
	else
	{
		pc = e.pc + 4;
	}
}

std::shared_ptr<trace> trace::open(const std::string &file_name)
{
	std::shared_ptr<trace> ret;
	auto file = std::make_shared<std::ifstream>(file_name, std::ios::in |
			std::ios::binary | std::ios::ate);
	if (!file->is_open())
	{
		return std::shared_ptr<trace>(nullptr);
	}
	auto size = file->tellg();
	char buffer[trace_v2_traits::offset + 1];
	buffer[trace_v2_traits::offset] = 0;
	file->seekg(0);
	file->read((char*)&buffer, trace_v2_traits::offset);
	file->seekg(0);
	std::string header(buffer+1, trace_v2_traits::offset-1);
	if (header != "CheriStreamTrace")
	{
		ret = make_trace<trace_v1_traits>(file, size);
	}
	else
	{
		if (buffer[0] - 0x80 != 2)
		{
			throw std::invalid_argument("Unrecognised trace file version");
		}
		ret = make_trace<trace_v2_traits>(file, size);
	}
	return ret;
}
void trace_segment::add_entry(disassembler::disassembler &d,
                              keyframe &kf,
                              const debug_trace_entry &entry)
{
	kf.update(entry, d);
	entries.push_back(entry);
	regs.push_back(kf.regs);
	debug_trace_entry &e = entries.back();
	if (e.pc == 0)
	{
		e.pc = kf.pc;
	}
}

