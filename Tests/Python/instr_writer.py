"""
Test trace writer python interface
"""
import tempfile
import pytest

import pycheritrace as pct

@pytest.fixture
def trace():

    with tempfile.NamedTemporaryFile() as tracefile:
        yield tracefile

@pytest.fixture
def asm():
    asm = pct.assembler()
    assert asm
    return asm

instr = [("daddiu $1, $1, 64\n", 0x40002164),
         ("nop\n", 0x00000000),
         ("ld $1, 0x10($4)", 0x100081dc),
         ("jalr $t9", 0x09f82003),
         ("csc $c1, $at, 0x10($c4)", 0x010824f8),
         ("cincoffset $c12, $c2, $at", 0x4010ac49),
         ("cgetpccsetoffset $c1, $at\n", 0xff090148),
         ("cjalr $c12, $c17\n", 0x0060f148)]

@pytest.mark.parametrize("expr,expected", instr)
def test_assemble(asm, expr, expected):
    opcode = asm.assemble(expr)
    assert opcode == expected, \
        "Can not assemble %s %x != %x" % (expr, opcode, expected)

def test_write_entry(asm, trace):

    writer = pct.trace_writer.open(trace.name)
    assert writer is not None

    entry = pct.debug_trace_entry()
    entry.pc = 0xdeadc0de;
    entry.cycles = 100;
    entry.inst = asm.assemble("daddiu $1, $1, 64")
    entry.reg_value_set(64)
    entry.reg_num = 1
    entry.is_store = False
    entry.is_load = False
    writer.append(entry)

    reader = pct.trace.open(trace.name)
    assert reader is not None
    assert reader.size() == 1
    reader.seek_to(0)
    result = reader.get_entry()
    assert result.pc == entry.pc
    assert result.cycles == entry.cycles
    assert result.inst == entry.inst
    assert result.reg_value_gp() == 64
    assert result.reg_num == entry.reg_num
    assert result.is_store == entry.is_store
    assert result.is_load == entry.is_load
    assert result.memory_address == 0
