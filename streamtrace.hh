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

namespace cheri {
namespace streamtrace {
/**
 * Format for on-disk trace entries.  These are all stored in CHERI native
 * endian (big endian).
 */
struct debug_trace_entry_disk {
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
struct debug_trace_entry_disk_v1 {
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
struct debug_trace_entry {
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
	 * The value of the cycle counter (a 10-bit counter that wraps on
	 * overflow).
	 */
	uint64_t    cycles;
	/**
	 * The instruction being executed.
	 */
	uint32_t    inst;
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
struct capability_register {
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
struct register_set {
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

/**
 * Abstract (public) superclass for a streamtrace.
 */
struct trace {
	/**
	 * Callback that is invoked while the streamtrace is being loaded.  The
	 * parameters are a pointer to the trace that is being loaded, the number
	 * of trace entries loaded so far, and whether the stream has finished
	 * loading.  The return value should be true if the traces should continue
	 * loading, false otherwise.
	 */
	typedef std::function<bool(trace*, uint64_t, bool)> notifier;
	/**
	 * Returns the number of entries in the trace.
	 */
	virtual uint64_t size() = 0;
	/**
	 * Seek to a specific point in the streamtrace.
	 */
	virtual bool seek_to(uint64_t offset) = 0;
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
}
} // namespace cheri
