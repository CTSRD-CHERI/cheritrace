#include "streamtrace.hh"
#include <assert.h>

using cheri::streamtrace::debug_trace_entry;

static uint64_t pcs[] = {
	0xffffffff8024d188,
	0xffffffff8024d18c,
	0xffffffff8024d190,
	0xffffffff8024d194,
	0xffffffff8024d198
};
static uint32_t instrs[] = {
	0x1800b3df,
	0x1000b2df,
	0x800b1df,
	0xb0df,
	0x800e003
};

int main()
{
	// Test opening a simple v1 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/short.trace");
	uint64_t count = 0;
	trace->scan([&](debug_trace_entry e, uint64_t idx) {
				assert(idx == count);
				count++;
				return false;
			});
	assert(count == 5);
	count = 0;
	trace->scan([&](debug_trace_entry e, uint64_t idx) {
				assert(idx == count);
				count++;
				if (count == 2)
				{
					return true;
				}
				return false;
			});
	assert(count == 2);
	trace->scan([&](debug_trace_entry e, uint64_t idx) {
				assert(e.pc == pcs[idx]);
				assert(e.inst == instrs[idx]);
				return false;
			});
	return 0;
}
