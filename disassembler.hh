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

#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInstPrinter.h"

#pragma once

namespace cheri {
namespace disassembler  {

struct instruction_info {
	enum instruction_type {
		unknown = 0,
		flow_control,
		memory_access
	} type = unknown;
	std::string name;
	bool is_call = false;
	bool is_return = false;
	bool has_delay_slot = false;
	int destination_register = -1;
};

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


class disassembler {
	std::unique_ptr<llvm::MCContext> mccontext;
	std::unique_ptr<llvm::MCDisassembler> disAsm;
	std::unique_ptr<llvm::MCInstPrinter> instrPrinter;
	int registerIndexForLLVMRegNo(unsigned regNo);
public:
	disassembler();
	instruction_info &&disassemble(uint32_t);
};



} //namespace disassembler 
}// namespace cheri
