/*-
 * Copyright (c) 2015 David T. Chisnall
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once
#include <memory>
#include <string>

namespace cheri {

/**
 * Class representing an address map.
 */
struct addressmap
{
	/**
	 * A single mapping.  
	 */
	struct range
	{
		/**
		 * The start of this address range.
		 */
		uint64_t start = 0;
		/**
		 * The end of this range;
		 */
		uint64_t end = 0;
		/**
		 * The name of the mapped file.
		 */
		std::string file_name;
		/**
		 * Is this file mapped with read permissions?
		 */
		bool is_readable : 1;
		/**
		 * Is this file mapped with write permissions?
		 */
		bool is_writeable : 1;
		/**
		 * Is this file mapped with execute permissions?
		 */
		bool is_executable : 1;
	};
	/**
	 * Construct a new address map by parsing a procstat file.
	 */
	static std::shared_ptr<addressmap> open_procstat(std::string path);
	/**
	 * For a given address, return the file that is mapping it.  If the
	 * specified address is not within any address range then it will return a
	 * zero-length address range.
	 */
	virtual range mapping_for_address(uint64_t) = 0;
	/**
	 * Virtual destructor.
	 */
	virtual ~addressmap();
};


} // namespace cheri
