#include "streamtrace.hh"
#include "disassembler.hh"

#include <assert.h>
#include <iostream>
#include <sstream>

using cheri::streamtrace::debug_trace_entry;
using cheri::streamtrace::register_set;
using namespace std;

#define CAP_REG(x) 64 + x

vector<string> split(const string &str, char delim)
{
	vector<string> elems;
	stringstream ss(str);
	string itm;
	while (getline(ss, itm, delim))
	{
		elems.push_back(itm);
	}
	return elems;
}

int main()
{
	// Test opening a simple v1 format trace
	auto trace = cheri::streamtrace::trace::open(SOURCE_PATH "/csetbounds.trace");
	
	auto success = trace->seek_to(14);
	assert(success);
	auto regs = trace->get_regs();
	assert(regs.cap_reg[1].base == 0x00);
	assert(regs.cap_reg[1].offset == 0x12007b900);
	assert(regs.cap_reg[1].length == 0x10000000000);
	
	success = trace->seek_to(15);
	assert(success);
	regs = trace->get_regs();
	assert(regs.cap_reg[3].base == 0x12007b900);
	assert(regs.cap_reg[3].offset == 0);
	assert(regs.cap_reg[3].length == 3);
	return 0;
}
