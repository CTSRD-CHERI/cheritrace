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

#include <string>
#include <memory>

#pragma once

namespace cheri {
namespace disassembler  {

/**
 * Information about an instruction.
 */
struct instruction_info {
	/**
	 * Enumeration used to classify instructions.
	 */
	enum instruction_type {
		unknown = 0,
		flow_control,
		memory_access
	};
	/**
	 * The type of the instruction.
	 */
	instruction_type type = unknown;
	/**
	 * The disassembled instruction.
	 */
	std::string name;
	/**
	 * Is this a call instruction?
	 */
	bool is_call = false;
	/**
	 * Is this a return instruction?
	 */
	bool is_return = false;
	/**
	 * Is this an instruction that has a delay slot?
	 */
	bool has_delay_slot = false;
	/**
	 * Which register is the destination for this instruction?
	 */
	int destination_register = -1;
};

/**
 * The names of instructions, indexed by the values stored in
 * `destination_register` in the `instruction_info` field.
 */
static const char* const MipsRegisterNames[] = {
	"zero", "at", "v0", "v1",
	"a0", "a1", "a2", "a3",
	"t0", "t1", "t2", "t3",
	"t4", "t5", "t6", "t7",
	"s0", "s1", "s2", "s3",
	"s4", "s5", "s6", "s7",
	"t8", "t9", "k0", "k1",
	"gp", "sp", "fp", "ra"
};

struct disassembler_impl;

/**
 * Public interface to the disassembler.  Note that this is not safe to use
 * across threads.
 */
class disassembler {
	disassembler_impl *pimpl;
public:
	/**
	 * Construct a new disassembler.
	 */
	disassembler();
	/**
	 * Destructor.
	 */
	~disassembler();
	/**
	 * Disassemble an instruction and return information about it.
	 */
	instruction_info disassemble(uint32_t);
};



} //namespace disassembler 
}// namespace cheri
