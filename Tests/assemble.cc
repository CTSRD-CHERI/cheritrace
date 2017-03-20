#include "disassembler.hh"
#include <assert.h>

std::vector<std::tuple<std::string, uint32_t>> test_instructions =
	{std::make_tuple("daddiu $1, $1, 64\n", 0x40002164),
	 std::make_tuple("nop\n", 0x00000000),
	 std::make_tuple("ld $1, 0x10($4)", 0x100081dc),
	 std::make_tuple("jalr $t9", 0x09f82003),
	 std::make_tuple("csc $c1, $at, 0x10($c4)", 0x010824f8),
	 std::make_tuple("cincoffset $c12, $c2, $at", 0x4010ac49),
	 std::make_tuple("cgetpccsetoffset $c1, $at\n", 0xff090148),
	 std::make_tuple("cjalr $c12, $c17\n", 0x0060f148)};

int main()
{	
	// Test assembling some instructions
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
