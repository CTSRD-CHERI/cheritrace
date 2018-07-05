#include "streamtrace.hh"
#include "disassembler.hh"
#include <assert.h>

#include <iostream>

int main()
{
	// Test opening a simple v1 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/caphwreg_test.cvtrace");
	assert(trace);
	cheri::disassembler::disassembler dis;

	auto expect_asm = [&](int i, int target_reg)
		{
			bool success = trace->seek_to(i);
			assert(success);
			auto entry = trace->get_entry();
			auto info = dis.disassemble(entry.inst);
			assert(info.destination_register == target_reg);
		};
	expect_asm(2, 127);
	return 0;
}
