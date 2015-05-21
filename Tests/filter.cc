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
	// Check that we can filter a trace
	auto filtered = trace->filter([&](debug_trace_entry e) {
			return (count++ % 2) == 0; });
	assert(filtered->size() == 3);
	filtered->scan([&](debug_trace_entry e, uint64_t idx) {
				assert(e.pc == pcs[idx*2]);
				assert(e.inst == instrs[idx*2]);
				return false;
			});
	count = 0;
	// Check that we can filter a filtered trace
	auto filtered2 = filtered->filter([&](debug_trace_entry e) {
			return count++ < 2; });
	assert(filtered2->size() == 2);
	filtered2->scan([&](debug_trace_entry e, uint64_t idx) {
				assert(e.pc == pcs[idx*2]);
				assert(e.inst == instrs[idx*2]);
				return false;
			});
	auto inverted = filtered2->inverted_view();
	return 0;
}
