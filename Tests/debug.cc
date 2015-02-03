#include "objectfile.hh"
#include <assert.h>

using namespace cheri::objectfile;

int main()
{
	auto file = file::open(SOURCE_PATH "/hello_world");
	assert(file);
	auto info = file->debug_info_for_address(0x120000be0);
	assert(info.file == "hello.c");
	assert(info.line == 4);
	assert(info.column == 0);
#ifdef XFAIL
	assert(info.func == "main");
#endif
}
