import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import is_valid_email


def _match_time(n):
    """Wall-clock seconds to reject a bounded adversarial input of length n+1."""
    evil = "a" * n + "!"
    start = time.perf_counter()
    is_valid_email(evil)
    return time.perf_counter() - start


def test_benign_input_is_valid():
    assert is_valid_email("user@example.com") is True


def test_match_time_stays_flat():
    # The same adversarial inputs the vulnerable pattern chokes on finish almost
    # instantly here; the linear pattern cannot backtrack, so time stays flat.
    t_small = _match_time(20)
    t_large = _match_time(24)
    assert t_large < 0.05
    assert t_small < 0.05
