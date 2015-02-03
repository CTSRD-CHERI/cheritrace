#include "objectfile.hh"
#include "disassembler.hh"
#include <assert.h>

#include <stdio.h>
using namespace cheri::objectfile;

int main()
{
	auto file = file::open(SOURCE_PATH "/hello_world");
	assert(file);
	auto info = file->function_at_address(0x120000be0);
	cheri::disassembler::disassembler dis;
	uint32_t instr = (*info)[0];
	auto result = dis.disassemble(instr).name;
	assert(result == "	daddiu	$sp, $sp, -160");
}
