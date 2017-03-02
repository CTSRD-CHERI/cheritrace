"""
py.test version of test on the short.trace sample file
"""
import os
import pytest

import pycheritrace as pct

@pytest.fixture()
def tracefile():
    ctest_src_path = os.environ["CTEST_SOURCE_PATH"]
    return os.path.join(ctest_src_path, "short.trace")

@pytest.fixture()
def pcs():
    prog_counters = [0xffffffff8024d188,
	             0xffffffff8024d18c,
	             0xffffffff8024d190,
	             0xffffffff8024d194,
	             0xffffffff8024d198]
    return prog_counters

@pytest.fixture()
def instrs():
    inst_list = [0x1800b3df,
	         0x1000b2df,
	         0x800b1df,
	         0xb0df,
	         0x800e003]
    return inst_list

def assert_disasm_trace(trace, index, disassembler, expected):
    __tracebackhide__ = True
    seek_ok = trace.seek_to(index)
    assert seek_ok, "Failed to seek trace to index #%d" % index
    entry = trace.get_entry()
    assert entry is not None, "Failed to get trace entry #%d" % index
    info = disassembler.disassemble(entry.inst)
    if info.name != expected:
        pytest.fail("Disasm failed (entry #%d) found %s, expected %s" %
                    (index, info.name, expected))

def assert_regval(registers, index, value):
    # __tracebackhide__ = True
    # register $0 is not stored, index registers from 1
    index -= 1
    assert registers.gpr[index] == value
    assert registers.valid_gprs[index]
                            
def test_simple(tracefile):
    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
    assert trace.size() == 5

def test_disassemble(tracefile):
    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
    dis = pct.disassembler()
    assert dis is not None, "Failed to create disassembler"

    result = dis.disassemble(0x2e08048) 
    assert result.name == "\tmtc2\t$zero, $28, 2"
    assert result.destination_register == 28

    assert_disasm_trace(trace, 0, dis, "\tld\t$19, 24($sp)")
    assert_disasm_trace(trace, 1, dis, "\tld\t$18, 16($sp)")
    assert_disasm_trace(trace, 2, dis, "\tld\t$17, 8($sp)")
    assert_disasm_trace(trace, 3, dis, "\tld\t$16, 0($sp)")
    assert_disasm_trace(trace, 4, dis, "\tjr\t$ra")

def test_regvalues(tracefile):
    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile

    seek_ok = trace.seek_to(4)
    assert seek_ok, "Failed to seek trace to index #4"

    registers = trace.get_regs()
    assert registers is not None, "Failed to get trace registers"
    assert_regval(registers, 19, 0x7fffffe1a0)
    assert_regval(registers, 18, 0x9800000002b3e000)
    assert_regval(registers, 17, 0xc0000000150b7780)
    assert_regval(registers, 16, 0xc0000000150b7530)

def test_scan_simple(tracefile, pcs, instrs):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
    state = {"n_call": 0}

    def scanner(e, idx):
        state["n_call"] += 1
        assert e.pc == pcs[idx]
        assert e.inst == instrs[idx]
        return False

    trace.scan(scanner)
    assert state["n_call"] == 5
    trace.scan(scanner, 0, 42, pct.trace.backwards)
    assert state["n_call"] == 10

def test_scan_backwards(tracefile, pcs, instrs):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
    state = {"n_call": 0, "idx": 5}

    def scanner(e, idx):
        state["n_call"] += 1
        assert state["idx"] > idx
        state["idx"] = idx
        assert e.pc == pcs[idx]
        assert e.inst == instrs[idx]
        return False

    trace.scan(scanner, 2, 4, pct.trace.backwards)
    assert state["n_call"] == 3

def test_detail_scan_backwards(tracefile, pcs, instrs):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
    state = {"n_call": 0, "idx": 5}

    def scanner(e, regs, idx):
        state["n_call"] += 1
        assert state["idx"] > idx
        state["idx"] = idx
        assert e.pc == pcs[idx]
        assert e.inst == instrs[idx]
        return False

    trace.scan(scanner, 2, 4, pct.trace.backwards)
    assert state["n_call"] == 3
    
def test_filter(tracefile, pcs, instrs):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile

    context = {
        "count": 0
    }
        
    def filter_1(e):
        keep = (context["count"] % 2) == 0
        context["count"] += 1
        return keep

    def filter_2(e):
        keep = context["count"] < 2
        context["count"] += 1
        return keep

    def scanner(e, idx):
        assert e.pc == pcs[idx]
        assert e.inst == instrs[idx]
        return False

    # filter once
    filtered = trace.filter(filter_1)
    assert filtered.size() == 3
    filtered.scan(scanner)
    # reset context
    context["count"] = 0
    
    # filter again
    filtered2 = filtered.filter(filter_2)
    assert filtered2.size() == 2
    filtered2.scan(scanner)

    # invert view
    inverted = filtered2.inverted_view()
    assert inverted.size() == 3
    inverted.scan(scanner)

def test_scan(tracefile, pcs, instrs):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
        
    context = {
        "count": 0,
        "regs_tested": False
    }
    
    def scanner_simple(e, idx):
            assert idx == context["count"]
            context["count"] += 1
            return False
            
    def scanner_stop(e, idx):
            assert idx == context["count"]
            context["count"] += 1
            return context["count"] == 2

    def scanner_entry(e, idx):
            assert e.pc == pcs[idx]
            assert e.inst == instrs[idx]
            return False
            
    def scanner_detail(e, r, idx):
            assert e.pc == pcs[idx]
            assert e.inst == instrs[idx]
            if (idx == 4):
                def expect_regval(reg, val):
                    reg -= 1
                    assert r.gpr[reg] == val
                    assert r.valid_gprs[reg]
                context["regs_tested"] = True
                expect_regval(19, 0x7fffffe1a0);
                expect_regval(18, 0x9800000002b3e000);
                expect_regval(17, 0xc0000000150b7780);
                expect_regval(16, 0xc0000000150b7530);
            return False

    trace.scan(scanner_simple)
    assert context["count"] == 5
    context["count"] = 0
    
    trace.scan(scanner_stop)
    assert context["count"] == 2
    context["count"] = 0
    
    trace.scan(scanner_entry)
    trace.scan(scanner_detail, 0, trace.size())
    assert context["regs_tested"]
    
