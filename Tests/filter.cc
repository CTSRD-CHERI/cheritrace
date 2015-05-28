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

template<class T>
void check(T &trace)
{
	trace->scan([&](debug_trace_entry e, uint64_t idx) {
				assert(e.pc == pcs[idx]);
				assert(e.inst == instrs[idx]);
				return false;
			});
	// Check that scanning backwards also works
	trace->scan([&](debug_trace_entry e, uint64_t idx) {
				assert(e.pc == pcs[idx]);
				assert(e.inst == instrs[idx]);
				return false;
			}, 0, 42, cheri::streamtrace::trace::backwards);
}

int main()
{
	// Test opening a simple v1 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/short.trace");
	check(trace);
	uint64_t count = 0;
	// Check that we can filter a trace
	auto filtered = trace->filter([&](debug_trace_entry e) {
			return (count++ % 2) == 0; });
	assert(filtered->size() == 3);
	check(filtered);
	count = 0;
	// Check that we can filter a filtered trace
	auto filtered2 = filtered->filter([&](debug_trace_entry e) {
			return count++ < 2; });
	assert(filtered2->size() == 2);
	check(filtered2);
	auto inverted = filtered2->inverted_view();
	return 0;
}
