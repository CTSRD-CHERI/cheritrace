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
#include "objectfile.hh"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCDisassembler/MCRelocationInfo.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"


#include <cxxabi.h>

using namespace __cxxabiv1;
using namespace cheri;
using namespace objectfile;
using llvm::object::symbol_iterator;
using llvm::Expected;
using llvm::StringRef;

namespace llvm {
	extern const llvm::MCInstrDesc MipsInsts[];
}

namespace {

class concrete_file;

/**
 * Concrete subclass of `function` that implements the real behaviour.
 */
class concrete_function : public function
{
	/**
	 * The file that contains this function.  The `buffer` is owned by the
	 * file, so the file must persist for at least as long as each function.
	 */
	std::shared_ptr<concrete_file> file;
	/**
	 * The base address of the function.
	 */
	uint64_t base;
	/**
	 * The demangled version of the function name.
	 */
	std::string name;
	/**
	 * The mangled version of the function name.
	 */
	std::string mangled;
	/**
	 * The name of the section that contains this function (normally .text).
	 */
	std::string sectionName;
	/**
	 * The buffer.  This is a reference into data owned by the file.
	 */
	StringRef buffer;
	public:
	/**
	 * Constructor.  Creates a new function object referring to the specified
	 * file.
	 */
	concrete_function(std::shared_ptr<concrete_file> &&f,
	                  uint64_t start,
	                  StringRef contents,
	                  StringRef mangledName,
	                  StringRef secName) :
		file(f), base(start), mangled(mangledName.str()), sectionName(secName.str()),
		buffer(contents)
	{
		size_t length;
		int status;
		char *buffer = __cxa_demangle(mangled.c_str(), nullptr, &length, &status);
		if (status == 0)
		{
			std::string demangled(buffer, length);
			name = std::move(demangled);
			free(buffer);
		}
		else
		{
			name = mangled;
		}
	}
	const std::string mangled_name() const override
	{
		return mangled;
	}
	const std::string demangled_name() const override
	{
		return name;
	}
	uint64_t size() const override
	{
		return buffer.size();
	}
	uint64_t base_address() const override
	{
		return base;
	}
	virtual const std::string section_name() const override
	{
		return sectionName;
	}
	uint32_t operator[](uint64_t idx) const override
	{
		uint32_t val = buffer[idx++];
		val <<=8;
		val |= (unsigned char)buffer[idx++];
		val <<=8;
		val |= (unsigned char)buffer[idx++];
		val <<=8;
		val |= (unsigned char)buffer[idx];
		return cheri_byte_order_to_host(val);
	}
};

/**
 * Concrete subclass of `file`.  Subclasses `std::enable_shared_from_this` to
 * allow the `function_at_address` to pass a `std::shared_ptr` to the
 * `concrete_function` constructor.
 */
class concrete_file : public file, public std::enable_shared_from_this<concrete_file>
{
	/**
	 * The LLVM object representing the file.
	 */
	llvm::object::OwningBinary<llvm::object::ObjectFile> objectFileHolder;
	/**
	 * LLVM object file object.  Owned by `objectFileHolder`.
	 */
	llvm::object::ObjectFile *objectFile = nullptr;
	/**
	 * Debug info context associated with the file.  Used to implement the
	 * `debug_info_for_address()` method.
	 */
	std::unique_ptr<llvm::DWARFContext> debugInfo = nullptr;
	public:
	std::shared_ptr<function> function_at_address(uint64_t address) override;
	/**
	 * Initialise the object.  This is not in the constructor, to allow better
	 * handling in case of failure.
	 */
	bool init(const std::string file)
	{
		assert(!objectFile);
		auto of = llvm::object::ObjectFile::createObjectFile(file);
		if (!of)
		{
			return false;
		}
		objectFileHolder = std::move(of.get());
		objectFile = objectFileHolder.getBinary();
		debugInfo = llvm::DWARFContext::create(*objectFile);
		return true;
	}
	line_info debug_info_for_address(uint64_t address) override;
};




}// anonymous namespace
std::shared_ptr<file> file::open(const std::string &file)
{
	auto ret = std::make_shared<concrete_file>();
	if (!ret->init(file))
	{
		return nullptr;
	}
	return ret;
}

namespace {
template<typename T, typename S>
bool isInRange(S &secOrSym, T &start, T size, T address)
{
	Expected<T> Start = secOrSym.getAddress();
	if (!Start)
	{
		return false;
	}
	start = Start.get();
	if ((start > address) || (address > (start+size)))
	{
		return false;
	}
	return true;
}
}

std::shared_ptr<function> concrete_file::function_at_address(uint64_t address)
{
	auto shared_this = shared_from_this();
	using namespace llvm::object;
	debug_info_for_address(address);
	// See if we can find a symbol with the correct name
	for (const SymbolRef &sym : objectFile->symbols())
	{
		uint64_t size = ELFSymbolRef(sym).getSize();
		uint64_t start;
		if (!isInRange(sym, start, size, address))
		{
			continue;
		}
		Expected<StringRef> name = sym.getName();
		if (!name)
		{
			continue;
		}
		section_iterator iter((SectionRef()));
		Expected<section_iterator> section = sym.getSection();
		if (!section)
		{
			continue;
		}
		SectionRef sec = *section.get();
    Expected<StringRef> secName = sec.getName();
    if (!secName)
    {
      continue;
    }
    Expected<StringRef> secContents = sec.getContents();
    if (!secContents)
    {
      continue;
    }
    StringRef contents = secContents.get().substr(start - sec.getAddress(), size);
		return std::make_shared<concrete_function>(
				std::move(shared_this),
				start,
				contents,
				std::move(name.get()),
				std::move(secName.get()));
	}
	for (const SectionRef &sec : objectFile->sections())
	{
		uint64_t size = sec.getSize();
		uint64_t start;
		if (!isInRange(sec, start, size, address))
		{
			continue;
		}
		Expected<StringRef> secName = sec.getName();
    if (!secName)
    {
      continue;
    }
    Expected<StringRef> secContents = sec.getContents();
    if (!secContents)
    {
      continue;
    }
		return std::make_shared<concrete_function>(
				std::move(shared_this),
				start,
				secContents.get(),
				secName.get(),
				secName.get());
	}

	return nullptr;
}
line_info concrete_file::debug_info_for_address(uint64_t address)
{
	if (debugInfo == nullptr)
	{
		return {"","",0,0};
	}
  llvm::object::SectionedAddress secAddress = {
    .Address = address,
    .SectionIndex = llvm::object::SectionedAddress::UndefSection
  };
	auto line = debugInfo->getLineInfoForAddress(secAddress);
	line_info li = {line.FileName, line.FunctionName, line.Line, line.Column };
	return li;
}

function::~function() {}
file::~file() {}
