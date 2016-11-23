"""
Test advanced instruction parsing that exposes all the instruction operands
"""
import os
import pytest

import pycheritrace as pct

@pytest.fixture
def trace():
    ctest_src_path = os.environ["CTEST_SOURCE_PATH"]
    trace_path = os.path.join(ctest_src_path, "csetbounds.trace")
    trace = pct.trace.open(trace_path)
    assert trace is not None
    return trace

@pytest.fixture
def disasm():
    dis = pct.disassembler()
    assert dis
    return dis

def get_inst_at(trace, dis, index):
    seek_ok = trace.seek_to(index)
    assert seek_ok
    entry = trace.get_entry()
    assert entry
    inst = dis.disassemble(entry.inst)
    return inst

def assert_is_register(op):
    assert op.is_valid
    assert op.is_register
    assert not op.is_immediate
    assert not op.is_fp_immediate
    assert not op.is_expr
    assert not op.is_inst

def assert_is_immediate(op):
    assert op.is_valid
    assert not op.is_register
    assert op.is_immediate
    assert not op.is_fp_immediate
    assert not op.is_expr
    assert not op.is_inst

def assert_is_expr(op):
    assert op.is_valid
    assert not op.is_register
    assert not op.is_immediate
    assert not op.is_fp_immediate
    assert op.is_expr
    assert not op.is_inst

def test_daddiu(trace, disasm):
    """
    Test parsing for daddiu $5, $0, 3
    """
    inst = get_inst_at(trace, disasm, 4)
    assert len(inst.operands) == 3
    op0,op1,op2 = inst.operands
    assert_is_register(op0)
    assert_is_register(op1)
    assert_is_immediate(op2)
    assert op0.register_number == 5
    assert op1.register_number == 0
    assert op2.immediate == 3

def test_cfromptr(trace, disasm):
    """
    Test parsing for cfromptr $c1, $c0, $4
    """
    inst = get_inst_at(trace, disasm, 13)
    assert len(inst.operands) == 3
    op0,op1,op2 = inst.operands
    assert_is_register(op0)
    assert_is_register(op1)
    assert_is_register(op2)
    assert op0.register_number == 65
    assert op1.register_number == 64
    assert op2.register_number == 4

def test_store(trace, disasm):
    """
    Test parsing of store instruction with offset
    sd      $4, 16($fp)
    """
    inst = get_inst_at(trace, disasm, 10)
    assert len(inst.operands) == 3
    op0,op1,op2 = inst.operands
    assert_is_register(op0)
    assert_is_register(op1)
    assert_is_immediate(op2)
    assert op0.register_number == 4
    assert op1.register_number == 30
    assert op2.immediate == 16

def test_cap_store(trace, disasm):
    """
    Test parsing of capability store instruction with offset
    csb     $25, $zero, 0($c3)
    """
    inst = get_inst_at(trace, disasm, 27)
    assert len(inst.operands) == 4
    op0,op1,op2,op3 = inst.operands
    assert_is_register(op0)
    assert_is_register(op1)
    assert_is_immediate(op2)
    assert_is_register(op3)
    assert op0.register_number == 25
    assert op1.register_number == 0
    assert op2.immediate == 0
    assert op3.register_number == 67

def test_cap_load(trace, disasm):
    """
    Test parsing of capability load instruction with offset
    clb     $25, $zero, 1($c3)
    """
    inst = get_inst_at(trace, disasm, 29)
    assert len(inst.operands) == 4
    op0,op1,op2,op3 = inst.operands
    assert_is_register(op0)
    assert_is_register(op1)
    assert_is_immediate(op2)
    assert_is_register(op3)
    assert op0.register_number == 25
    assert op1.register_number == 0
    assert op2.immediate == 1
    assert op3.register_number == 67

def test_jalr(trace, disasm):
    """
    Test parsing of jalr
    jalr    $25
    """
    inst = get_inst_at(trace, disasm, 5)
    assert len(inst.operands) == 2
    op0,op1 = inst.operands
    assert_is_register(op0)
    assert_is_register(op1)
    assert op0.register_number == 31
    assert op1.register_number == 25

def test_nop(trace, disasm):
    """
    Test parsing of nop
    """
    inst = get_inst_at(trace, disasm, 6)
    assert len(inst.operands) == 3
    op0,op1,op2 = inst.operands
    assert_is_register(op0)
    assert_is_register(op1)
    assert_is_immediate(op2)
    assert op0.register_number == 0
    assert op1.register_number == 0
    assert op2.immediate == 0
