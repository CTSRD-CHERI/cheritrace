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
#include <vector>

#pragma once

namespace cheri {
namespace disassembler  {

/**
 * Information about an instruction operand
 */
struct operand_info {
	/**
	 * Is the operand valid?
	 */
	bool is_valid;
	/**
	 * Is the operand a register?
	 */
	bool is_register;
	/**
	 * Is the operand an immediate?
	 */
	bool is_immediate;
	/**
	 * Is floating point immediate?
	 */
	bool is_fp_immediate;
	/**
	 * Is expression? (MCExpr*)
	 * XXX what is this exactly
	 */
	bool is_expr;
	/**
	 * Is inst? (MCInst*)
	 * XXX what is this exactly
	 */
	bool is_inst;
	/**
	 * Operand register number, this is valid only
	 * if the operand is a register.
	 */
	int register_number;
	/**
	 * Operand immediate value, this is valid only
	 * if the operand is an immediate.
	 */
	int64_t immediate;
	/**
	 * Operand floating point immediate value, this
	 * is valid only if the operand is a float immediate.
	 */
	double fp_immediate;
};

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
	 * Which register is the destination for this instruction?  GPRs are
	 * numbered 0-31, floating point registers from 32-63, capability registers
	 * from 64-95.
	 */
	int destination_register = -1;
	/**
	 * Operands of the instruction
	 */
	std::vector<operand_info> operands;
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
	"gp", "sp", "fp", "ra",
	"d0", "d1", "d2", "d3",
	"d4", "d5", "d6", "d7",
	"d8", "d9", "d10", "d11",
	"d12", "d13", "d14", "d15",
	"d16", "d17", "d18", "d19",
	"d20", "d21", "d22", "d23",
	"d24", "d25", "d26", "d27",
	"d28", "d29", "d30", "d31",
	"c0", "c1", "c2", "c3",
	"c4", "c5", "c6", "c7",
	"c8", "c9", "c10", "c11",
	"c12", "c13", "c14", "c15",
	"c16", "c17", "c18", "c19",
	"c20", "c21", "c22", "c23",
	"c24", "c25", "c26", "c27",
	"c28", "c29", "c30", "c31",
	"chwr_ddc", "chwr_userlocal", "chwr2", "chwr3",
	"chwr4", "chwr5", "chwr6", "chwr7",
	"chwr_priv_userlocal", "chwr9", "chwr10", "chwr11",
	"chwr12", "chwr13", "chwr14", "chwr15",
	"chwr16", "chwr17", "chwr18", "chwr19",
	"chwr20", "chwr21", "chwr_kr1c", "chwr_kr2c",
	"chwr24", "chwr25", "chwr26", "chwr27",
	"chwr28", "chwr_kcc", "chwr_kdc", "chwr_epcc"
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

struct assembler_impl;

class assembler {
	std::unique_ptr<assembler_impl> pimpl;
public:
	assembler();
	~assembler();
	/**
	 * Assemble a single instruction.
	 * Note that the result endianness is the one of the target
	 * and not the one of the host.
	 */
	uint32_t assemble(const std::string &asmexpr);
};

} //namespace disassembler
}// namespace cheri
