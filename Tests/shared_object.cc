#include "objectfile.hh"
#include <assert.h>

using namespace cheri::objectfile;

int main()
{
	auto file = file::open(SOURCE_PATH "/libhello.so");
	assert(file);
	auto func = file->function_at_address(0x878);
	assert(func);
	assert(func->base_address() == 0x860);
	assert(func->mangled_name() == "hi");
	assert(func->demangled_name() == "hi");
	assert(func->section_name() == ".text");
	assert((*func)[0] == 0xe0ffbd67);
}
