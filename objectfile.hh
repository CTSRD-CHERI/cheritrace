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

#include <memory>
#include <string>

namespace cheri {

namespace objectfile {


/**
 * A function within an object file.
 */
struct function
{
	/**
	 * The name of the function, as it appears in the object file.
	 */
	virtual const std::string mangled_name() const = 0;
	/**
	 * The name demangled, assuming that it is a C++ function.  This will be
	 * the same as the `mangled_name()` if the symbol is not a C++ name.
	 */
	virtual const std::string demangled_name() const = 0;
	/**
	 * The name of the section that this function appears in.
	 */
	virtual const std::string section_name() const = 0;
	/**
	 * The size of the function, in bytes.
	 */
	virtual uint64_t size() const = 0;
	/**
	 * The address of the start of the function.
	 */
	virtual uint64_t base_address() const = 0;
	/**
	 * Read one instruction (32 bits) of data from the function.  The result is
	 * in the host byte order.
	 */
	virtual uint32_t operator[](uint64_t idx) const = 0;
};

/**
 * Line info from the debug metadata.
 */
struct line_info
{
	/**
	 * The name of the source file containing the address.
	 */
	std::string file;
	/**
	 * The name of the function at this address.
	 *
	 * Note: An LLVM bug is currently preventing this from working.
	 */
	std::string function;
	/**
	 * The line number within the source file.
	 */
	uint32_t line;
	/**
	 * The column  number within the source line.
	 */
	uint32_t column;
};

/**
 * An object file.
 */
struct file
{
	/**
	 * Return a function object for the function that exists at this address
	 * within the object file.
	 */
	virtual std::shared_ptr<function> function_at_address(uint64_t address) = 0;
	/**
	 * Find the debug info for an address within the object file.
	 */
	virtual line_info debug_info_for_address(uint64_t address) = 0;
	/**
	 * Open an object file and return an object representing it.
	 */
	static std::shared_ptr<file> open(const std::string &);
};


} // namespace objectfile
}// namespace cheri
