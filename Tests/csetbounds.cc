#include "streamtrace.hh"
#include "disassembler.hh"

#include <assert.h>
#include <iostream>
#include <sstream>

using cheri::streamtrace::capability_register;
using cheri::streamtrace::register_set;
using cheri::streamtrace::debug_trace_entry;
using cheri::streamtrace::trace;
using namespace std;

#define CAP_REG(x) 64 + x

struct reg_info {
     int index;
     int regnum;
     capability_register cap;
};

static struct reg_info registers[] = {
	/*
	 * XXXAM: rerun the test program with the fixed qemu to generate a trace
	 * with the correct valid and sealed bits.
	 */
	/* index, regnum, {base, length, offset, type, perms, valid, (un?)sealed} */
	{3, 1, {0x00, 0x12053e000, 0x1200e4100, 0x00, 0x0000817d, 1, 0}}, // cfromptr
	{4, 1, {0x1200e4100, 0x28, 0x00, 0x00, 0x0000817d, 1, 0}}, // csetbounds
	{27, 2, {0x00, 0x12053e000, 0x1200e4128, 0x00, 0x0000817d, 1, 0}}, // cfromptr
	{28, 2, {0x1200e4128, 0x28, 0x00, 0x00, 0x0000817d, 1, 0}}, // csetbounds
	{47, 1, {0x1200e4100, 0x28, 0x04, 0x00, 0x0000817d, 1, 0}}, // cincoffset
	{-1, -1, 0} /* sentinel */
};

void
assert_cap_equal(capability_register &reg, capability_register &expect)
{
	assert(reg.base == expect.base);
	assert(reg.offset == expect.offset);
	assert(reg.length == expect.length);
	assert(reg.permissions == expect.permissions);
	assert(reg.type == expect.type);
	assert(reg.valid == expect.valid);
	assert(reg.unsealed == expect.unsealed);
}

int main()
{
	/* Check that capability registers are updated correctly */
	auto trace = trace::open(SOURCE_PATH "/csetbounds.trace");

	struct reg_info *info = registers;
	bool success;
	register_set regset;
	debug_trace_entry entry;
      
	while (info->index > 0) {
		success = trace->seek_to(info->index);
		assert(success);
		regset = trace->get_regs();
		entry = trace->get_entry();
		assert(info->regnum == entry.capreg_number());
		assert_cap_equal(regset.cap_reg[info->regnum], info->cap);
		info++;
	}
	return 0;
}
