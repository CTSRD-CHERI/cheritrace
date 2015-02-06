#include "streamtrace.hh"
#include "disassembler.hh"
#include <assert.h>

#include <iostream>

int main()
{
	// Test opening a v2 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/v2.trace");
	assert(trace);
	cheri::disassembler::disassembler dis;
	auto expect_asm = [&](int i, std::string str)
		{
			bool success = trace->seek_to(i);
			assert(success);
			auto entry = trace->get_entry();
			auto info = dis.disassemble(entry.inst);
			//std::cout << "'" << info.name << "'vs'" << str << "'" << std::endl;
			assert(info.name == str);
		};
	expect_asm(0, "	rdhwr	$16, $2");
	expect_asm(1, "	ld	$1, 13904($1)");
	expect_asm(2, "	move	 $2, $4");
	expect_asm(3, "	ld	$25, -21456($gp)");
	expect_asm(4, "	cfromptr $c5, $c0, $zero");
	return 0;
}
