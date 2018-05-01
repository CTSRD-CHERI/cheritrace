#include "streamtrace.hh"
#include <fstream>
#include <cstdio>
#include <condition_variable>
#include <mutex>
#include <assert.h>

using namespace cheri::streamtrace;

std::mutex mtx;
std::condition_variable preload_done;

int main()
{
	std::string tmp = std::tmpnam(nullptr);

	// Test opening a trace with a notifier callback
	auto notify = [&, tmp](trace *tr, uint64_t entries, bool done) -> bool
		{
			if (done) {
				std::lock_guard<std::mutex> lock(mtx);
				tr->save_keyframes(tmp);
				preload_done.notify_one();
			}
			return false;
		};
	std::unique_lock<std::mutex> lock(mtx);
	auto trace = trace::open(SOURCE_PATH "/long.trace", notify);
	preload_done.wait(lock);

	/* now try to reload the trace with the keyframes */
	auto trace2 = trace::open(SOURCE_PATH "/long.trace", tmp);

	debug_trace_entry entry;

	assert(trace2->seek_to(100));
	entry = trace2->get_entry();

	assert(entry.inst == 0x0360a1c9);
	assert(entry.pc == 0x9000000040000d64);
	assert(entry.memory_address == 0x9000000040027ff0);
	
	return 0;
}
