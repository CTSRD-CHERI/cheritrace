#include "streamtrace.hh"
#include <assert.h>

int main()
{
	// Test opening a simple v1 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/short.trace");
	assert(trace);
	assert(trace->size() == 5);
	return 0;
}
