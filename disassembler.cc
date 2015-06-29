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
#include "disassembler.hh"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCRelocationInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInstPrinter.h"


#include <mutex>
#include <assert.h>

using namespace cheri::disassembler;

namespace llvm {
	extern const MCInstrDesc MipsInsts[];
}
using llvm::MipsInsts;

static int registerIndexForString(const char *str)
{
	if (str[0] == '$')
	{
		str++;
	}
	char *end;
	if (str[0] == 'c')
	{
		str++;
		long idx = strtol(str, &end, 10);
		if (str == end)
		{
			return -1;
		}
		return idx + 64;
	}
	if (str[0] == 'f')
	{
		str++;
		long idx = strtol(str, &end, 10);
		if (str == end)
		{
			return -1;
		}
		return idx + 32;
	}
	long idx = strtol(str, &end, 10);
	if (str != end)
	{
		return (int)idx;
	}
	for (size_t i=0 ; i<(sizeof(MipsRegisterNames) / sizeof(*MipsRegisterNames)) ; i++)
	{
		if (strcmp(str, MipsRegisterNames[i]) == 0)
		{
			return (int)i;
		}
	}
	return -1;
}
namespace cheri {
namespace disassembler{
struct disassembler_impl 
{
	/**
	 * LLVM machine code context.
	 */
	std::unique_ptr<llvm::MCContext> mccontext;
	/**
	 * LLVM disassembler.
	 */
	std::unique_ptr<llvm::MCDisassembler> disAsm;
	/**
	 * LLVM instruction printer.
	 */
	std::unique_ptr<llvm::MCInstPrinter> instrPrinter;
	/**
	 * Map from LLVM's notion of registers to something stable.
	 */
	int registerIndexForLLVMRegNo(unsigned regNo);
	disassembler_impl();
};
}
} // cheri::disassembler

int disassembler_impl::registerIndexForLLVMRegNo(unsigned regNo)
{
	std::string regName;
	llvm::raw_string_ostream regStream(regName);
	instrPrinter->printRegName(regStream, regNo);
	return registerIndexForString(regStream.str().c_str());
}

static std::unique_ptr<const llvm::MCRegisterInfo> mri;

disassembler::disassembler()
{
	pimpl = new disassembler_impl();
}

disassembler::~disassembler()
{
	delete pimpl;
}
disassembler_impl::disassembler_impl()
{
	static const llvm::Target *target;
	static std::unique_ptr<const llvm::MCAsmInfo> asmInfo;
	static std::unique_ptr<const llvm::MCSubtargetInfo> sti;
	static std::unique_ptr<const llvm::MCInstrInfo> mii;
	static std::unique_ptr<const llvm::MCInstrAnalysis> mia;
	static std::once_flag flag;

	LLVMInitializeMipsTargetInfo();
	LLVMInitializeMipsTargetMC();
	LLVMInitializeMipsAsmParser();
	LLVMInitializeMipsDisassembler();


	std::call_once(flag, [](){ 
		std::string cheriTriple("cheri-unknown-freebsd");
		std::string mipsTriple("mips64-unknown-freebsd");
		std::string triple = cheriTriple;
		std::string features("");
		const llvm::MCRegisterInfo *MRI = nullptr;

		std::string Error;

		target = llvm::TargetRegistry::lookupTarget(triple, Error);
		if (target)
		{
			MRI = target->createMCRegInfo(triple);
		}
		// First try to set up the target for CHERI, if it doesn't work then fall back to MIPS
		if (MRI == 0)
		{
			triple = mipsTriple;
			target = llvm::TargetRegistry::lookupTarget(triple, Error);
			if (target)
			{
				MRI = target->createMCRegInfo(triple);
			}
		}
		assert(MRI != 0);
		mri.reset(MRI);
		assert(mri && "Failed to create MCRegisterInfo");
		asmInfo.reset(target->createMCAsmInfo(*mri, triple));
		assert(asmInfo && "Failed to create MCAsmInfo");
		sti.reset(target->createMCSubtargetInfo(triple, "", features));
		assert(sti && "Failed to create MCSubtargetInfo");
		mii.reset(target->createMCInstrInfo());
		assert(mii && "Failed to create MCInstrInfo");
		mia.reset(new llvm::MCInstrAnalysis(mii.get()));
		assert(mia && "Failed to create MCInstrAnalysis");
	});
	assert(mri);
	mccontext.reset(new llvm::MCContext(asmInfo.get(), mri.get(), nullptr));
	disAsm.reset(target->createMCDisassembler(*sti, *mccontext));
	assert(disAsm && "Failed to create MCDisassembler");
	instrPrinter.reset(target->createMCInstPrinter(
		asmInfo->getAssemblerDialect(), *asmInfo, *mii, *mri, *sti));
	assert(instrPrinter && "Failed to create MCInstPrinter");
}


instruction_info disassembler::disassemble(uint32_t anInstruction)
{
	assert(pimpl->mccontext->getAsmInfo());
	instruction_info info;
	uint8_t instbytes[4];
	std::memcpy(instbytes, &anInstruction, sizeof(anInstruction));
	static_assert(sizeof(anInstruction) == sizeof(instbytes),
			"Instruction size is wrong!");
	llvm::MCInst inst;
	uint64_t size;
	auto status = pimpl->disAsm->getInstruction(inst, size, instbytes, 0,
			llvm::errs(), llvm::errs());
	if (status != llvm::MCDisassembler::Success)
	{
		info.name = "<Unable to disassemble>";
		return std::move(info);
	}
	llvm::raw_string_ostream os(info.name);
	pimpl->instrPrinter->printInst(&inst, os, "");
	os.str();
	auto &desc = MipsInsts[inst.getOpcode()];
	if (desc.isBranch() || desc.isCall() || desc.isReturn())
	{
		info.type = instruction_info::flow_control;
	}
	else if (desc.mayLoad() || desc.mayStore())
	{
		info.type = instruction_info::memory_access;
	}
	info.has_delay_slot = desc.hasDelaySlot();
	// The MIPS back end currently uses a pseudo for returns and so the
	// disassembled instruction is not identifiable as a return.
	info.is_return = (anInstruction == 0x03e00008) || desc.isReturn();
	info.is_call = desc.isCall();
	const uint16_t *implicitDefs = desc.getImplicitDefs();
	unsigned numImplicitDefs = desc.getNumImplicitDefs();
	for (unsigned i=0 ; i<numImplicitDefs ; i++)
	{
		int regNo = pimpl->registerIndexForLLVMRegNo(implicitDefs[i]);
		if (regNo >= 0)
		{
			info.destination_register = regNo;
			break;
		}
	}
	if ((info.destination_register == -1) && (inst.getNumOperands() > 0))
	{
		llvm::MCOperand op0 = inst.getOperand(0);
		if (op0.isReg())
		{
			if (desc.hasDefOfPhysReg(inst, op0.getReg(), *mri.get()))
			{
				int regNo = pimpl->registerIndexForLLVMRegNo(op0.getReg());
				if (regNo >= 0)
				{
					info.destination_register = regNo;
				}
			}
		}
	}
	return std::move(info);
}

/*
struct instruction_info {
	int destination_register;
};
*/
