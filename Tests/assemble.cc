#include "disassembler.hh"
#include <assert.h>
#include <iostream>

std::vector<std::tuple<std::string, uint32_t>> test_instructions =
	{std::make_tuple("daddiu $1, $1, 64\n", 0x64210040),
	 std::make_tuple("nop\n", 0x00000000),
	 std::make_tuple("ld $1, 0x10($4)\n", 0xdc810010),
	 std::make_tuple("jalr $t9\n", 0x0320f809),
	 std::make_tuple("csc $c1, $at, 0x10($c4)\n", 0xf8240801),
	 std::make_tuple("cincoffset $c12, $c2, $at\n", 0x49ac1040),
	 std::make_tuple("cgetpccsetoffset $c1, $at\n", 0x480109ff),
	 std::make_tuple("cjalr $c12, $c17\n", 0x48f16000)};

int main()
{	
	// Test opening a simple v1 format trace
	cheri::disassembler::assembler as;
	uint32_t result;

	for (auto& entry : test_instructions) {
		auto asm_expr = std::get<0>(entry);
		auto expect = std::get<1>(entry);
		result = as.assemble(asm_expr);
		assert(result == expect);
	}
	return 0;
}
