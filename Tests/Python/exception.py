"""
Test exception propatagation from the python callbacks to the
python caller of the scan/filter methods.
"""

import os
import pytest

import pycheritrace as pct

@pytest.fixture()
def tracefile():
    ctest_src_path = os.environ["CTEST_SOURCE_PATH"]
    return os.path.join(ctest_src_path, "short.trace")

def test_scan_builtin_exception(tracefile):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile

    def scanner(e, idx):
        raise ValueError("TESTING")

    with pytest.raises(ValueError):
        trace.scan(scanner)

def test_scan_custom_exception(tracefile):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile

    class MyException(Exception):
        pass

    def scanner(e, idx):
        raise MyException("TESTING")

    with pytest.raises(MyException):
        trace.scan(scanner)

@pytest.mark.skip(reason="Not implemented yet")
def test_filter_builtin_exception(tracefile):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
        
    def filter_(e):
        raise ValueError("TESTING")

    with pytest.raises(ValueError):
        trace.filter(filter_)

def test_detail_scan_builtin_exception(tracefile):

    trace = pct.trace.open(tracefile)
    assert trace is not None, "Failed to open tracefile %s" % tracefile

    def scanner(e, r, idx):
        print("Scanning", idx)
        raise ValueError("TESTING")

    with pytest.raises(ValueError):
        trace.scan(scanner, 0, trace.size())
