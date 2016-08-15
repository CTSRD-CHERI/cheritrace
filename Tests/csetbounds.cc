#include "streamtrace.hh"
#include "disassembler.hh"

#include <assert.h>
#include <iostream>
#include <sstream>

using cheri::streamtrace::capability_register;
using cheri::streamtrace::register_set;
using cheri::streamtrace::trace;
using namespace std;

#define CAP_REG(x) 64 + x

struct reg_info {
     int index;
     int regnum;
     capability_register cap;
};

static struct reg_info registers[] = {
     {14, 1, {0x00, 0x10000000000, 0x12007b900, 0x01000000, 0x00, 0, 0}},
     {15, 3, {0x12007b900, 0x03, 0x00, 0x01000000, 0x00, 0, 0}},
     {26, 3, {0x61, 0x03, 0x00, 0x80000000, 0x0000807d, 1, 0}},
     {26, 3, {0x61, 0x03, 0x00, 0x80000000, 0x0000807d, 1, 0}},
     {29, 3, {0x31, 0x03, 0x00, 0x80000000, 0x0000807d, 1, 0}},
     {32, 3, {0x30, 0x03, 0x00, 0x80000000, 0x0000807d, 1, 0}},
     {-1, -1, 0} /* sentinel */
};

bool
assert_cap_equal(capability_register &reg, capability_register &expect)
{
     printf("%lx %lx\n", reg.base, expect.base);
     assert(reg.base == expect.base);
     assert(reg.offset == expect.offset);
     assert(reg.length == expect.length);
     assert(reg.permissions == expect.permissions);
     assert(reg.type == expect.type);
     assert(reg.valid == expect.valid);
     assert(reg.unsealed == expect.unsealed);
}

int main()
{
     /* Check that capability registers are updated correctly */ 
     auto trace = trace::open(SOURCE_PATH "/csetbounds.trace");

     struct reg_info *info = registers;
     bool success;
     register_set regset;
      
     while (info->index > 0) {
	  success = trace->seek_to(info->index);
	  assert(success);
	  regset = trace->get_regs();
	  assert_cap_equal(regset.cap_reg[info->regnum], info->cap);
	  info++;
     }
     return 0;
}
