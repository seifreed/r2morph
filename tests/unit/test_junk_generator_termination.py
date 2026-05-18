"""
Regression test: JunkGenerator.generate_junk_code must always terminate.

generate_junk_code(size) entered an infinite loop for any 0 < size <= 16:
when no register was stored yet (always true at entry for a small budget)
the `if available <= 16: continue` path restarted the loop without
consuming `available`, emitting code, or breaking, so it spun forever.
That hung any caller requesting a small amount of junk
(e.g. pattern_pool / pattern_integration with a small/derived size).

These tests use the real JunkGenerator (no mocks, no monkeypatch) and run
it in a daemon thread with a join timeout, so a pre-fix infinite loop
leaves the thread alive and fails the assertion without blocking pytest;
post-fix the call returns quickly.
"""

import threading

from r2morph.mutations.junk_generator import JunkGenerator

# Generous: post-fix generate_junk_code(<=64) returns in well under a
# second; only a genuine infinite loop reaches this bound.
_TIMEOUT_SECONDS = 20.0


def _run_with_timeout(size: int) -> bytes:
    box: dict[str, bytes] = {}

    def worker() -> None:
        box["result"] = JunkGenerator(os_type="linux").generate_junk_code(size)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=_TIMEOUT_SECONDS)

    assert not thread.is_alive(), f"generate_junk_code({size}) did not terminate (infinite loop)"
    assert "result" in box
    return box["result"]


def test_generate_junk_code_small_size_terminates() -> None:
    # 0 < size <= 16: every register is unstored at entry, so pre-fix this
    # hit `if available <= 16: continue` forever.
    result = _run_with_timeout(8)
    assert isinstance(result, bytes)


def test_generate_junk_code_boundary_sizes_terminate() -> None:
    for size in (1, 15, 16, 17):
        result = _run_with_timeout(size)
        assert isinstance(result, bytes)


def test_generate_junk_code_normal_size_terminates_and_emits() -> None:
    result = _run_with_timeout(64)
    assert isinstance(result, bytes)
    assert len(result) > 0
