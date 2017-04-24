#include "disassembler.hh"
#include "streamtrace.hh"
#include <assert.h>

using namespace cheri;
using namespace disassembler;
using namespace streamtrace;

int main()
{
	// Test the trace writer with some entries
	assembler as;

	// truncate the outfile if existed
	std::ofstream f("out.trace", std::ios::trunc);
	f.close();

	auto writer = trace_writer::open("out.trace");
	debug_trace_entry entry;
	// mips entry
	entry.pc = 0xdeadc0de0;
	entry.cycles = 1;
	entry.inst = as.assemble("daddiu $at, $at, 64\n");
	entry.reg_value.gp = 64;
	entry.exception = 31; /* no exception */
	entry.reg_num = 1;
	entry.is_store = false;
	entry.is_load = false;
	writer->append(entry);
	// capability instruction entry
	entry.pc = 0xdeadc0de4;
	entry.cycles = 2;
	entry.inst = as.assemble("cincoffset $c2, $c1, $at\n");
	entry.reg_value.cap.base = 0x1000;
	entry.reg_value.cap.offset = 0x1000;
	entry.reg_value.cap.length = 0x2000;
	entry.reg_value.cap.type = 0x123456; /* 24bit */
	entry.reg_value.cap.permissions = 0xbeef; /* 16bit */
	entry.reg_value.cap.valid = true;
	entry.reg_value.cap.unsealed = true;
	entry.exception = 31; /* no exception */
	entry.reg_num = 66; /* cap regs number in 64-95 */
	entry.is_store = false;
	entry.is_load = false;
	writer->append(entry);

	auto trace = trace::open("out.trace");
	assert(trace->size() == 2);
	trace->seek_to(0);
	auto result = trace->get_entry();
	assert(result.pc == 0xdeadc0de0);
	assert(result.cycles == 1);
	assert(result.inst == as.assemble("daddiu $at, $at, 64\n"));
	assert(result.reg_value.gp == 64);
	assert(result.exception == 31);
	assert(result.reg_num == 1);
	assert(result.is_store == false);
	assert(result.is_load == false);

	trace->seek_to(1);
	result = trace->get_entry();
	assert(result.pc == 0xdeadc0de4);
	assert(result.cycles == 2);
	assert(result.inst == as.assemble("cincoffset $c2, $c1, $at\n"));
	assert(result.reg_value.cap.base == 0x1000);
	assert(result.reg_value.cap.offset == 0x1000);
	assert(result.reg_value.cap.length == 0x2000);
	assert(result.reg_value.cap.type == 0x123456);
	assert(result.reg_value.cap.permissions == 0xbeef);
	assert(result.reg_value.cap.valid == true);
	assert(result.reg_value.cap.unsealed == true);
	assert(result.exception == 31);
	assert(result.reg_num == 66);
	assert(result.is_store == false);
	assert(result.is_load == false);
	return 0;
}
