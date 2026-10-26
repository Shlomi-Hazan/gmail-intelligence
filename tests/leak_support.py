"""Test support: keep a KNOWN production resource leak from contaminating other tests.

Background (CI run 40383476752, Python 3.14): a few production code paths leave a SQLite connection open when they raise on a damaged or locked file
(`ReadOnlyIndex.__init__` in index.py, `_connect` users in maintenance.py). The connection is closed only when the garbage collector finalises it, and its
ResourceWarning is printed at that moment, possibly inside ANOTHER test that captures stderr and compares it exactly. The production fix is pending owner approval.
Until then the tests that trigger such a path are decorated with `isolate_known_leaks`: the leaked object is finalised right after the test that caused it, so the warning
cannot land in a later test. The suppression is scoped to that one `gc.collect()` call and to ResourceWarning only; nothing else is hidden and no other test is affected.
Set GI_REPORT_KNOWN_LEAKS=1 to let those warnings through (this is how the remaining leaks are inventoried).
"""
import functools
import gc
import os
import warnings


def isolate_known_leaks(test):
    @functools.wraps(test)
    def wrapper(*args, **kwargs):
        try:
            return test(*args, **kwargs)
        finally:
            if os.environ.get("GI_REPORT_KNOWN_LEAKS"):
                gc.collect()
            else:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", ResourceWarning)
                    gc.collect()
    return wrapper
