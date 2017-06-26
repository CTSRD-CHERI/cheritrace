"""
Test the deferred preloading for linear scanning.
"""
import os
import pytest

import pycheritrace as pct

@pytest.fixture()
def tracefile():
    ctest_src_path = os.environ["CTEST_SOURCE_PATH"]
    return os.path.join(ctest_src_path, "long.trace")

def test_deferred_scan(tracefile):
    trace = pct.trace.open(tracefile, None, True)

