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
namespace disassembler
{
	class disassembler;
}
namespace streamtrace
{
#ifndef SIZE_T_MAX
#define SIZE_T_MAX SIZE_MAX
#endif
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
 * Format for Qemu on-disk trace entries.  These are all stored in big
 * endian.
 */
struct debug_trace_entry_disk_v3
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
	 * A 3rd version-specific value associated with the trace entry.
	 */
	uint64_t    val3;
	/**
	 * A 4th version-specific value associated with the trace entry.
	 */
	uint64_t    val4;
	/**
	 * A 5th version-specific value associated with the trace entry.
	 */
	uint64_t    val5;
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
	 * The type of the capability (only applies to sealed capabilities).
	 */
	uint32_t type;
	/**
	 * A bitfield representing the capability.
	 */
	uint16_t permissions;
	/**
	 * Is the capability valid?
	 */
	bool valid:1;
	/**
	 * Is the capability unsealed?
	 */
	bool unsealed:1;
};

static_assert(sizeof(capability_register) <= 32,
              "Capability register structure has grown far too big!");

union debug_trace_register
{
	/**
	 * The capability register value, if this trace entry contains a
	 * capability register.
	 */
	capability_register cap;
	/**
	 * The general-purpose register value, if this trace entry contains a
	 * general-purpose register.
	 */
	uint64_t            gp;
};
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
	 * The number of cycles since the start of the streamtrace.
	 */
	uint64_t    cycles;
	/**
	 * The value of the register that is defined by this trace entry.  This is
	 * usually the destination register, but is the source register for loads.
	 */
	union debug_trace_register reg_value;
	/**
	 * The address used for load or store instructions.
	 */
	uint64_t    memory_address;
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
	 * The exception that fired during this instruction (0 for no exception).
	 */
	uint8_t     exception;
	/**
	 * Is this a load instruction?  If so, the `address` field indicates the
	 * source address.
	 */
	bool        is_load:1;
	/**
	 * Is this a store instruction?  If so, the `address` field indicates the
	 * destination.
	 */
	bool        is_store:1;
	/**
	 * The register number for the register.  GPRs are numbered 0-31, floating
	 * point registers from 32-63, capability registers from 64-95.
	 */
	uint8_t     reg_num:8;
	int         register_number() const
	{
		if ((reg_num < 0) || (reg_num > 96))
		{
			return -1;
		}
		return reg_num;
	}
	/**
	 * Returns the GPR number for the value stored in `reg_value`.  If this
	 * instruction does not relate to a GPR, returns -1.
	 */
	int gpr_number() const
	{
		if (reg_num < 32)
		{
			return reg_num;
		}
		return -1;
	}
	/**
	 * Returns the FPR number for the value stored in `reg_value`.  If this
	 * instruction does not relate to a FPR, returns -1.
	 */
	int fpr_number() const
	{
		if ((reg_num > 31) && (reg_num < 64))
		{
			return reg_num - 32;
		}
		return -1;
	}
	/**
	 * Returns the capability register number for the value stored in
	 * `reg_value`.  If this instruction does not relate to a capability
	 * register, returns -1.
	 */
	int capreg_number() const
	{
		if ((reg_num > 63) && (reg_num < 96))
		{
			return reg_num - 64;
		}
		return -1;
	}
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
	 * Constructs an empty in-memory trace entry.
	 */
	debug_trace_entry();
	/**
	 * Constructs an in-memory trace entry from the v2 on-disk format.
	 */
	debug_trace_entry(const debug_trace_entry_disk &d, disassembler::disassembler &dis);
	/**
	 * Constructs an in-memory trace entry from the v3 on-disk format.
	 */
	debug_trace_entry(const debug_trace_entry_disk_v3 &d, disassembler::disassembler &dis);
	/**
	 * Constructs an in-memory trace entry from the v1 on-disk format.
	 */
	debug_trace_entry(const debug_trace_entry_disk_v1 &d, disassembler::disassembler &dis);
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
	/**
	 * Capability registers.
	 */
	std::array<capability_register, 32> cap_reg;
	/**
	 * Bitfield indicating whether the capability registers contain a known 
	 * value.  Note that this is distinct from the `valid` field in the
	 * `capability_register` structure, which indicates whether a known value
	 * is a valid capability.
	 */
	std::bitset<32> valid_caps = 0;
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
