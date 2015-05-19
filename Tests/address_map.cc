#include "addressmap.hh"
#include <assert.h>

#include <stdio.h>

using namespace cheri;

void check1(addressmap::range &r)
{
	assert(r.start == 0x400000);
	assert(r.end == 0x800000);
	assert(r.is_readable);
	assert(r.is_writeable);
	assert(!r.is_executable);
	assert(r.file_name == "");
}

void check2(addressmap::range &r)
{
	assert(r.start == 0x120000000);
	assert(r.end == 0x120004000);
	assert(r.is_readable);
	assert(!r.is_writeable);
	assert(r.is_executable);
	assert(r.file_name == "/home/theraven/a.out");
}

int main()
{
	auto map = addressmap::open_procstat(SOURCE_PATH "/procstat");
	auto r = map->mapping_for_address(0x120000000);
	check2(r);
	r = map->mapping_for_address(0x120004000);
	check2(r);
	r = map->mapping_for_address(0x120003000);
	check2(r);
	r = map->mapping_for_address(0x400000);
	check1(r);
	r = map->mapping_for_address(0x800000);
	check1(r);
	map = addressmap::open_procstat(SOURCE_PATH "/nonexistent");
	assert(map == nullptr);
	return 0;
}
