#include "streamtrace.hh"
#include <assert.h>

int main()
{
	// Test opening a v2 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/v2.trace");
	assert(trace);
	assert(trace->size() == 1076);
}
