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

    class py_scanner(pct.Scanner):
        def run(self, e, idx):
            assert e.pc == pcs[idx]
            assert e.inst == instrs[idx]
            return False

    # XXX: is it really needed? The scan method does not keep a reference
    # to the scanner after it completes
    scanner = py_scanner().__disown__() 
    trace.scan_trace(scanner)
    trace.scan_trace(scanner, 0, 42, pct.trace.backwards)

def test_filter(tracefile, pcs, instrs):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile

    class py_filter(pct.Filter):
        count = 0
        
        def run(self, e):
            keep = (py_filter.count % 2) == 0
            py_filter.count += 1
            return keep

    class py_filter_2(pct.Filter):
        count = 0
        
        def run(self, e):
            keep = py_filter_2.count < 2
            py_filter_2.count += 1
            return keep

    class py_scanner(pct.Scanner):
        def run(self, e, idx):
            assert e.pc == pcs[idx]
            assert e.inst == instrs[idx]
            return False

    # XXX: is it really needed? See scan()
    _filter = py_filter().__disown__()
    _filter2 = py_filter_2().__disown__()
    scanner = py_scanner().__disown__()

    # filter once
    filtered = trace.filter_trace(_filter)
    assert filtered.size() == 3
    filtered.scan_trace(scanner)

    # filter again
    filtered2 = filtered.filter_trace(_filter2)
    assert filtered2.size() == 2
    filtered2.scan_trace(scanner)

    # invert view
    inverted = filtered2.inverted_view()
    assert inverted.size() == 3
    inverted.scan_trace(scanner)

def test_scan(tracefile, pcs, instrs):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
        
    class py_scanner_simple(pct.Scanner):

        def __init__(self):
            pct.Scanner.__init__(self)
            self.count = 0
        
        def run(self, e, idx):
            assert idx == self.count
            self.count += 1
            return False
        
    class py_scanner_stop(pct.Scanner):
        
        def __init__(self):
            pct.Scanner.__init__(self)
            self.count = 0
            
        def run(self, e, idx):
            assert idx == self.count
            self.count += 1
            return self.count == 2

    class py_scanner_entry(pct.Scanner):
        def run(self, e, idx):
            assert e.pc == pcs[idx]
            assert e.inst == instrs[idx]
            return False

    class py_scanner_detail(pct.DetailedScanner):
        def __init__(self):
            pct.DetailedScanner.__init__(self)
            self.regs_tested = False
            
        def run(self, e, r, idx):
            assert e.pc == pcs[idx]
            assert e.inst == instrs[idx]
            if (idx == 4):
                def expect_regval(reg, val):
                    reg -= 1
                    assert r.gpr[reg] == val
                    assert r.valid_gprs[reg]
                self.regs_tested = True
                expect_regval(19, 0x7fffffe1a0);
                expect_regval(18, 0x9800000002b3e000);
                expect_regval(17, 0xc0000000150b7780);
                expect_regval(16, 0xc0000000150b7530);
            return False

    scan_simple = py_scanner_simple().__disown__()
    scan_stop = py_scanner_stop().__disown__()
    scan_entry = py_scanner_entry().__disown__()
    scan_detail = py_scanner_detail().__disown__()

    trace.scan_trace(scan_simple)
    assert scan_simple.count == 5
    trace.scan_trace(scan_stop)
    assert scan_stop.count == 2
    trace.scan_trace(scan_entry)
    trace.scan_trace(scan_detail, 0, trace.size())
    
