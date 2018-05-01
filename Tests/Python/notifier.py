"""
Check that the notifier callback works and can be called
"""
import os
import pytest
import threading

import pycheritrace as pct

@pytest.fixture()
def tracefile():
    ctest_src_path = os.environ["CTEST_SOURCE_PATH"]
    return os.path.join(ctest_src_path, "short.trace")

def test_notify(tracefile):

    evt = threading.Event()
    evt.clear()

    context = {
        "count": 0,
        "done": False
    }
    
    def notifier(trace, entries, done):
        context["count"] = entries
        if done:
            context["done"] = True
            evt.set()
        return False

    trace = pct.trace.open(tracefile, notifier)
    assert trace is not None, "Failed to open tracefile %s" % tracefile
    evt.wait()
    assert context["done"]
    assert context["count"] == trace.size()
