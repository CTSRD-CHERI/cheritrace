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
	entry.pc = 0xdeadc0de;
	entry.cycles = 1;
	entry.inst = as.assemble("daddiu $at, $at, 64\n");
	entry.reg_value.gp = 64;
	entry.exception = 31; /* no exception */
	entry.reg_num = 1;
	entry.is_store = false;
	entry.is_load = false;
	writer->append(entry);

	auto trace = trace::open("out.trace");
	assert(trace->size() == 1);
	trace->seek_to(0);
	auto result = trace->get_entry();
	assert(result.pc == entry.pc);
	assert(result.cycles == entry.cycles);
	assert(result.inst == entry.inst);
	assert(result.reg_value.gp == entry.reg_value.gp);
	assert(result.exception == entry.exception);
	assert(result.reg_num == entry.reg_num);
	assert(result.is_store == entry.is_store);
	assert(result.is_load == entry.is_load);
	return 0;
}
