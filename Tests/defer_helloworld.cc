#include "streamtrace.hh"
#include <assert.h>
#include <iostream>

using cheri::streamtrace::debug_trace_entry;
using cheri::streamtrace::register_set;
using cheri::streamtrace::trace;

int main()
{

	uint64_t preloaded_entries = 13045818;

	auto preload_callback = [&](trace *t, uint64_t entries, bool done) -> bool {		
		if (done) {
			assert(preloaded_entries == entries);
		}
		return false;
	};
	
	// Test opening a long (>10 keyframes) trace with deferred preloading
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/helloworld.cvtrace.xz",
						     preload_callback, true);
	uint64_t count = 0;
	int64_t idx_first = -1;

	/* during this scan only $at is valid */
	trace->scan([&](const debug_trace_entry &e, const register_set &regs, uint64_t idx) {
			if (idx_first == -1)
				idx_first = idx;
			count++;
			assert(e.cycles == count + 143388);
			return false;
		}, trace->size() / 2, trace->size(), 0);
	assert(count == 12902429);
	assert(idx_first == 12902429);
	return 0;
}
