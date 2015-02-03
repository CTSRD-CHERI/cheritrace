#include "streamtrace.hh"
#include <assert.h>

int main()
{
	// Test opening a simple v1 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/short.trace");
	assert(trace);
	bool success = trace->seek_to(4);
	assert(success);
	auto regs = trace->get_regs();
	auto expect_regval = [&](int reg, uint64_t val)
		{
			// Registers are indexed from 1 ($zero is not stored)
			reg -= 1;
			assert(regs.gpr[reg] == val);
			assert(regs.valid_gprs[reg]);
		};
	expect_regval(19, 0x7fffffe1a0LL);
	expect_regval(18, 0x9800000002b3e000LL);
	expect_regval(17, 0xc0000000150b7780LL);
	expect_regval(16, 0xc0000000150b7530LL);
	return 0;
}
