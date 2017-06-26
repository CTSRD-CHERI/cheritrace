"""
Test the deferred preloading for linear scanning.
"""
import os
import pytest

import pycheritrace as pct

@pytest.fixture()
def tracefile():
    ctest_src_path = os.environ["CTEST_SOURCE_PATH"]
    return os.path.join(ctest_src_path, "long.cvtrace")

def test_deferred_scan(tracefile):

    context = {
        "count": 0,
        "preloaded": 0,
    }

    def notifier(trace, entries, done):
        if done:
            context["preloaded"] = entries
        return False
    # XXX notifier not yet supported because of threading problems

    trace = pct.trace.open(tracefile, None, True)
    assert trace

    def scanner(e, regs, idx):
        context["count"] += 1
        assert regs.valid_caps.all()
        assert regs.valid_gprs.all()
        return False

    trace.scan(scanner, 8000, 9000, 0)
    assert context["count"] == 1001
    # assert context["preloaded"] == 4096
