#include "objectfile.hh"
#include <assert.h>

using namespace cheri::objectfile;

int main()
{
	auto file = file::open(SOURCE_PATH "/libhello.so");
	assert(file);
	auto info = file->debug_info_for_address(0x878);
	assert(info.file == "libhello.c");
	assert(info.line == 5);
	assert(info.column == 2);
#ifdef XFAIL
	assert(info.func == "hi");
#endif
}
