/*-
 * Copyright (c) 2015 David T. Chisnall
 * Copyright (c) 2017 Alfredo Mazzinghi
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

#include "streamtrace.hh"
#include "disassembler.hh"
#include <cstring>
#include <assert.h>

using namespace cheri;
using namespace streamtrace;

namespace {

std::ostream& operator<<(std::ostream &os, debug_trace_entry_disk_v3 &e)
{
	os.write(reinterpret_cast<char*>(&e), sizeof(e));
	return os;
}

enum class EntryVersion : uint8_t {
	CVT_GPR = 1,
	CVT_LD_GPR = 2,
	CVT_ST_GPR = 3,
	CVT_NO_REG = 4,
	CVT_CAP = 11,
	CVT_LD_CAP = 12,
	CVT_ST_CAP = 13
};

void encode_cap(const capability_register &cap, uint64_t *val2, uint64_t *val3,
		uint64_t *val4, uint64_t *val5)
{
	*val2 = (((uint64_t)cap.valid << 63) |
		 (((uint64_t)cap.type & 0xffffff) << 32) |
		 ((uint64_t)cap.permissions << 1) | cap.unsealed);
	*val3 = cap.offset + cap.base;
	*val4 = cap.base;
	*val5 = cap.length;
}
	
} // Anonymous namespace

std::shared_ptr<trace_writer> trace_writer::open(const std::string &file)
{
	return std::shared_ptr<trace_writer>(new trace_writer(std::move(file)));
}

trace_writer::trace_writer(const std::string &file) :
	tracefile(file, std::ios::app | std::ios::binary)
{
	assert(tracefile.is_open());
	tracefile.seekp(0, std::ios::end);
	size_t length = tracefile.tellp();
	char buffer[sizeof(debug_trace_entry_disk_v3)];
	if (length == 0) {
		buffer[0] = (char)0x83;
		std::memcpy(buffer+1, "CheriTraceV03", sizeof("CheriTraceV03"));
		tracefile.write(buffer, sizeof(buffer));
		cycles = 0;
	}
	else {
		size_t body = length - sizeof(debug_trace_entry_disk_v3);
		cycles = body / sizeof(debug_trace_entry_disk_v3);
		assert(body % sizeof(debug_trace_entry_disk_v3) == 0);
	}
}

bool trace_writer::append(const debug_trace_entry &entry)
{
	EntryVersion version;
	debug_trace_entry_disk_v3 disk_entry;
	disk_entry.exception = cheri_byte_order_to_host(entry.exception);
	disk_entry.cycles = cheri_byte_order_to_host((uint16_t)(entry.cycles & 0xffff));
	disk_entry.inst = cheri_byte_order_to_host(entry.inst);
	disk_entry.pc = cheri_byte_order_to_host(entry.pc);
	disk_entry.thread = cheri_byte_order_to_host(entry.thread);
	disk_entry.asid = cheri_byte_order_to_host(entry.asid);
	if (entry.is_store) {
		disk_entry.val1 = entry.memory_address;
		if (entry.capreg_number() != -1) {
			version = EntryVersion::CVT_ST_CAP;
			encode_cap(entry.reg_value.cap, &disk_entry.val2,
				   &disk_entry.val3, &disk_entry.val4,
				   &disk_entry.val5);
		}
		else {
			version = EntryVersion::CVT_ST_GPR;
			disk_entry.val2 = entry.reg_value.gp;
		}
	}
	else if (entry.is_load) {
		disk_entry.val1 = entry.memory_address;
		if (entry.capreg_number() != -1) {
			version = EntryVersion::CVT_LD_CAP;
			encode_cap(entry.reg_value.cap, &disk_entry.val2,
				   &disk_entry.val3, &disk_entry.val4,
				   &disk_entry.val5);
		}
		else {
			version = EntryVersion::CVT_LD_GPR;
			disk_entry.val2 = entry.reg_value.gp;
		}
	}
	else {
		if (entry.capreg_number() != -1 ||
		    entry.caphwreg_number() != -1) {
			version = EntryVersion::CVT_CAP;
			encode_cap(entry.reg_value.cap, &disk_entry.val2,
				   &disk_entry.val3, &disk_entry.val4,
				   &disk_entry.val5);
		}
		else if (entry.gpr_number() != -1 || entry.fpr_number() != -1) {
			version = EntryVersion::CVT_GPR;
			disk_entry.val2 = entry.reg_value.gp;
		}
		else {
			version = EntryVersion::CVT_NO_REG;
		}
	}
	disk_entry.val1 = cheri_byte_order_to_host(disk_entry.val1);
	disk_entry.val2 = cheri_byte_order_to_host(disk_entry.val2);
	disk_entry.val3 = cheri_byte_order_to_host(disk_entry.val3);
	disk_entry.val4 = cheri_byte_order_to_host(disk_entry.val4);
	disk_entry.val5 = cheri_byte_order_to_host(disk_entry.val5);
	disk_entry.version = static_cast<uint8_t>(version);
	tracefile << disk_entry;
	tracefile.flush();
	return true;
}
