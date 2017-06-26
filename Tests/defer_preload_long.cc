#include "streamtrace.hh"
#include <assert.h>
#include <iostream>

using cheri::streamtrace::debug_trace_entry;
using cheri::streamtrace::register_set;
using cheri::streamtrace::trace;

int main()
{

	uint64_t preloaded_entries;

	auto preload_callback = [&](trace *t, uint64_t entries, bool done) -> bool {		
		if (done) {
			std::cout << "n_entries " << entries << std::endl;
			assert(preloaded_entries == entries);
		}
		return false;
	};
	
	// Test opening a long (>2 keyframes) trace with deferred preloading
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/long.cvtrace",
						     preload_callback, true);
	uint64_t count = 0;
	int64_t idx_first = -1;

	preloaded_entries = 4096;
	/* during this scan only $at is valid */
	trace->scan([&](const debug_trace_entry &e, const register_set &regs, uint64_t idx) {
			if (idx_first == -1)
				idx_first = idx;
			assert(regs.valid_caps.none());
			assert(regs.valid_gprs.count() == 1);
			assert(regs.valid_gprs[0]);
			assert(regs.gpr[0] == 0x1b);
			count++;
			return false;
		}, 2049, 2080, 0);
	assert(count == 32);
	assert(idx_first == 2049);
	count = 0;
	idx_first = -1;

	/* during this scan all the registers must be valid 
	 * registers initialization starts at index 6156
	 * keyframes are at 0, 2048, 4096, 6144, 8192, 10240
	 */
	preloaded_entries = 4096;
	trace->scan([&](const debug_trace_entry &e, const register_set &regs, uint64_t idx) {
			if (idx_first == -1)
				idx_first = idx;
			assert(regs.valid_caps.all());
			assert(regs.valid_gprs.all());
			auto test_cap = [&](int n) {
				assert(regs.cap_reg[n].base == 0x1000);
				assert(regs.cap_reg[n].length == 0x1000);
				assert(regs.cap_reg[n].offset == n);
			};
			for (int i = 0; i < 32; i++)
				test_cap(i);
			for (int i = 1; i < 32; i++) {
				assert(regs.gpr[i - 1] == i);
			}
			count++;
			return false;
		}, 8000, 9000, 0);
	assert(count == 1001);
	assert(idx_first == 8000);

	return 0;
}
