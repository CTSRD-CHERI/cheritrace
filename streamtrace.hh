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

#include "cheri.hh"
#include <vector>
#include <memory>
#include <array>
#include <bitset>
#include <functional>

namespace cheri
{
namespace streamtrace
{
/**
 * Format for on-disk trace entries.  These are all stored in CHERI native
 * endian (big endian).
 */
struct debug_trace_entry_disk
{
	/**
	 * The version of the trace entry.  This is more accurately a type.
	 */
	uint8_t     version;
	/**
	 * The exception that fired during this instruction (0 for no exception).
	 */
	uint8_t     exception;
	/**
	 * The value of the cycle counter (a 10-bit counter that wraps on
	 * overflow).
	 */
	uint16_t    cycles;
	/**
	 * The instruction being executed.
	 */
	uint32_t    inst;
	/**
	 * The program counter value for the current point in the trace.
	 */
	uint64_t    pc;
	/**
	 * A version-specific value associated with the trace entry.
	 */
	uint64_t    val1;
	/**
	 * A second version-specific value associated with the trace entry.
	 */
	uint64_t    val2;
	/**
	 * The thread identifier for the hardware context that generated this trace
	 * event.
	 */
	uint8_t     thread;
	/**
	 * The address space identifier for the trace entry.  This can be used to
	 * extract traces for individual applications.
	 */
	uint8_t     asid;
} __attribute__((packed));

/**
 * Format for on-disk trace entries from older versions of berictl.  These are
 * all stored in CHERI native endian (big endian).
 */
struct debug_trace_entry_disk_v1
{
	/**
	 * The version of the trace entry.  This is more accurately a type.
	 */
	uint8_t     version;
	/**
	 * The exception that fired during this instruction (0 for no exception).
	 */
	uint8_t     exception;
	/**
	 * The value of the cycle counter (a 10-bit counter that wraps on
	 * overflow).
	 */
	uint16_t    cycles;
	/**
	 * The instruction being executed.
	 */
	uint32_t    inst;
	/**
	 * The program counter value for the current point in the trace.
	 */
	uint64_t    pc;
	/**
	 * A version-specific value associated with the trace entry.
	 */
	uint64_t    val1;
	/**
	 * A second version-specific value associated with the trace entry.
	 */
	uint64_t    val2;
} __attribute__((packed));

static_assert(sizeof(debug_trace_entry_disk_v1) == 32,
		"Debug trace record size is wrong!");

/**
 * The in-memory version of the debug trace entry.  Fields in this structure
 * are ordered by size so that they can be naturally aligned and have minimal
 * padding.
 */
struct debug_trace_entry
{
	/**
	 * The program counter value for the current point in the trace.
	 */
	uint64_t    pc;
	/**
	 * A version-specific value associated with the trace entry.
	 */
	uint64_t    val1;
	/**
	 * A second version-specific value associated with the trace entry.
	 */
	uint64_t    val2;
	/**
	 * The number of cycles since the start of the streamtrace.
	 */
	uint64_t    cycles;
	/**
	 * The instruction being executed.
	 */
	uint32_t    inst;
	/**
	 * The number of cycles between this instruction and the last.
	 */
	uint16_t    dead_cycles;
	/**
	 * The thread identifier for the hardware context that generated this trace
	 * event.
	 */
	uint8_t     thread;
	/**
	 * The address space identifier for the trace entry.  This can be used to
	 * extract traces for individual applications.
	 */
	uint8_t     asid;
	/**
	 * The version of the trace entry.  This is more accurately a type.
	 */
	uint8_t     version:3;
	/**
	 * The exception that fired during this instruction (0 for no exception).
	 */
	uint8_t     exception:5;
	/**
	 * Returns true if the program counter is in the range reserved for the
	 * kernel.
	 */
	bool is_kernel() const { return pc >= 0xFFFFFFFF0000000; }
	/**
	 * Returns true if the program counter is in the range reserved for the
	 * userspace programs.
	 */
	bool is_userspace() const { return !is_kernel(); }
	/**
	 * Constructs an in-memory trace entry from the v2 on-disk format.
	 */
	debug_trace_entry(const debug_trace_entry_disk &d) :
		pc(cheri_byte_order_to_host(d.pc)),
		val1(cheri_byte_order_to_host(d.val1)),
		val2(cheri_byte_order_to_host(d.val2)),
		cycles(cheri_byte_order_to_host(d.cycles)),
		inst(cheri_byte_order_to_host(d.inst)),
		thread(cheri_byte_order_to_host(d.thread)),
		asid(cheri_byte_order_to_host(d.asid)),
		version(d.version),
		exception(cheri_byte_order_to_host(d.exception)) {}
	/**
	 * Constructs an in-memory trace entry from the v1 on-disk format.
	 */
	debug_trace_entry(const debug_trace_entry_disk_v1 &d) :
		pc(cheri_byte_order_to_host(d.pc)),
		val1(cheri_byte_order_to_host(d.val1)),
		val2(cheri_byte_order_to_host(d.val2)),
		cycles(cheri_byte_order_to_host(d.cycles)),
		inst(cheri_byte_order_to_host(d.inst)),
		thread(0),
		asid(0),
		version(d.version),
		exception(cheri_byte_order_to_host(d.exception)) {}
};

/**
 * The values of a capability register.
 */
struct capability_register
{
	/**
	 * The base address.
	 */
	uint64_t base;
	/**
	 * The length of the capability.
	 */
	uint64_t length;
	/**
	 * The offset from the base of the capability.
	 */
	uint64_t offset;
	/**
	 * A bitfield representing the capability.
	 */
	uint16_t permissions;
};

/**
 * A snapshot of the CHERI register set at a specific point.
 */
struct register_set
{
	/**
	 * General purpose registers, represented as 64-bit integers.  Note that
	 * this numbers from 1: there is no point in storing the value of $0, as
	 * it always contains zero.
	 */
	std::array<uint64_t, 31> gpr = { { 0 } };
	/**
	 * Indicates whether registers have known values at this point in the
	 * trace.
	 */
	std::bitset<31> valid_gprs = 0;
	// Enable once we're actually processing things sensibly.
	//std::array<capability_register, 32> cap_reg;
	//std::bitset<31> valid_caps = 0;
};

struct trace_view;

/**
 * Abstract (public) superclass for a streamtrace.
 */
struct trace
{
	/**
	 * Bitmask values for defining scan options.
	 */
	enum scan_options
	{
		/**
		 * Iterate forwards.
		 */
		forewards = 0,
		/**
		 * Iterate backwards.  The end value will still be interpreted as the
		 * beginning point for iteration.
		 */
		backwards = 1
	};
	/**
	 * Callback that is invoked while the streamtrace is being loaded.  The
	 * parameters are a pointer to the trace that is being loaded, the number
	 * of trace entries loaded so far, and whether the stream has finished
	 * loading.  The return value should be false if the traces should continue
	 * loading, true otherwise.
	 */
	typedef std::function<bool(trace*, uint64_t, bool)> notifier;
	/**
	 * Callback for scanning the streamtrace.  The first argument is the trace
	 * entry, the second the index in the trace.  The function should return
	 * true to abort scanning, false otherwise.
	 *
	 * Note that, whether this is invoked on a trace or a view of a trace, the
	 * index is always the index into the underlying trace.  The scanner is
	 * always invoked in sequential order, so may keep track of the index into
	 * the trace view by using a variable bound to the closure.
	 */
	typedef std::function<bool(debug_trace_entry, uint64_t)> scanner;
	/**
	 * Variant of the streamtrace scanner that sees the register set as well as
	 * the trace entry.
	 */
	typedef std::function<bool(const debug_trace_entry&, const register_set &,
			uint64_t)> detailed_scanner;
	/**
	 * Predicate used for constructing trace filters.  Should return true if
	 * the trace entry is intended to be included in the trace, false
	 * otherwise.
	 */
	typedef std::function<bool(const debug_trace_entry&)> filter_predicate;
	/**
	 * Returns the number of entries in the trace.
	 */
	virtual uint64_t size() = 0;
	/**
	 * Seek to a specific point in the streamtrace.
	 */
	virtual bool seek_to(uint64_t offset) = 0;
	/**
	 * Returns the instruction number for the specified index.  In a normal
	 * trace, the return value will be the same as the argument.  In a trace
	 * view, it will be the index within the original trace.
	 */
	virtual uint64_t instruction_number_for_index(uint64_t) = 0;
	/**
	 * Returns the current trace entry.  It is undefined behaviour to call this
	 * method before calling `seek_to()`.
	 */
	virtual debug_trace_entry get_entry() = 0;
	/**
	 * Returns the contents of the register set at the current trace entry.  It
	 * is undefined behaviour to call this method before calling `seek_to()`.
	 */
	virtual register_set get_regs() = 0;
	/**
	 * Iterate over the stream trace, calling the argument function once for
	 * each trace element, continuing until either the callback returns `true`
	 * or the stream end is reached.
	 */
	virtual void scan(scanner) = 0;
	/**
	 * Iterate over a range within the trace, invoking the callback as in the
	 * single-argument version of this function.  The final argument is a set
	 * of flags formed by oring together values from the `scan_options`
	 * enumeration.
	 */
	virtual void scan(scanner, uint64_t start, uint64_t end, int opts=0) = 0;
	/**
	 * Scan over the trace providing full detail (including accurate cycle
	 * counts and the register set) to the scanner.
	 */
	virtual void scan(detailed_scanner, uint64_t, uint64_t, int opts=0) = 0;
	/**
	 * Filter this trace and return a view that only contains instructions that 
	 * match the underlying predicate.
	 */
	virtual std::shared_ptr<trace_view> filter(filter_predicate) = 0;
	/**
	 * Destructor.
	 */
	virtual ~trace();
	/**
	 * Constructs a new streamtrace from the specified file.
	 */
	static std::shared_ptr<trace> open(const std::string &file);
	/**
	 * Constructs a new streamtrace from the specified file and call the
	 * specified notifier as it loads.  Note that the notifier will be called
	 * from a separate thread - the user is responsible for ensuring that any
	 * required synchronisation is performed.
	 */
	static std::shared_ptr<trace> open(const std::string &file, notifier);
};
/**
 * A view on a streamtrace.
 */
struct trace_view : public trace
{
	/**
	 * Returns a new trace view that includes all of the entries in the
	 * underlying trace (not any intermediate trace views) that are not present
	 * in this trace.
	 */
	virtual std::shared_ptr<trace_view> inverted_view() = 0;
};
}
} // namespace cheri
