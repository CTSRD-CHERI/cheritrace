#include "objectfile.hh"
#include <assert.h>

using namespace cheri::objectfile;

int main()
{
	auto file = file::open(SOURCE_PATH "/hello_world");
	assert(file);
	auto func = file->function_at_address(0x120000be0);
	assert(func);
	assert(func->mangled_name() == "main");
	assert(func->demangled_name() == "main");
	assert(func->section_name() == ".text");
	assert((*func)[0] == 0x60ffbd67);
}
