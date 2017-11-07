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
	auto notify = [&](trace *tr, uint64_t entries, bool done) -> bool
		{
			if (done) {
				tr->save_keyframes(tmp);
				preload_done.notify_one();
			}
		};
	auto trace = trace::open(SOURCE_PATH "/short.trace", notify);
	std::unique_lock<std::mutex> lock;
	preload_done.wait(lock);

	/* now try to reload the trace with the keyframes */
	auto trace2 = trace::open(SOURCE_PATH "/short.trace", tmp);
	
	return 0;
}
