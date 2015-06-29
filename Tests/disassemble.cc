#include "streamtrace.hh"
#include "disassembler.hh"
#include <assert.h>

#include <iostream>

int main()
{
	// Test opening a simple v1 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/short.trace");
	assert(trace);
	cheri::disassembler::disassembler dis;

	auto result = dis.disassemble(0x2e08048);
	assert(result.name == "	cincbase	$c0, $c28, $zero");
	assert(result.destination_register == 64);

	auto expect_asm = [&](int i, std::string str)
		{
			bool success = trace->seek_to(i);
			assert(success);
			auto entry = trace->get_entry();
			auto info = dis.disassemble(entry.inst);
			std::cout << info.name << '\n';
			assert(info.name == str);
		};
	expect_asm(0, "	ld	$19, 24($sp)");
	expect_asm(1, "	ld	$18, 16($sp)");
	expect_asm(2, "	ld	$17, 8($sp)");
	expect_asm(3, "	ld	$16, 0($sp)");
	expect_asm(4, "	jr	$ra");
	return 0;
}
