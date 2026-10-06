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


def test_match_time_grows_super_linearly():
    # Two small, bounded input sizes. Catastrophic backtracking makes the larger
    # one dramatically slower; we measure the growth, never running to exhaustion.
    t_small = _match_time(20)
    t_large = _match_time(24)
    assert t_large > 0.1
    assert t_large / max(t_small, 1e-4) > 5
