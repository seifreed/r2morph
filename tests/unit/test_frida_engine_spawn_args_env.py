from __future__ import annotations

import os
from pathlib import Path

import pytest

from r2morph.instrumentation.frida_engine import FridaEngine, FRIDA_AVAILABLE


def test_frida_engine_spawn_with_args_and_env() -> None:
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)
    if not engine.initialize():
        pytest.skip("Frida device not available")

    target = Path("/bin/sleep")
    if not target.exists():
        pytest.skip("sleep binary not available")

    env = {"R2MORPH_TEST_ENV": "1"}
    env.update({k: v for k, v in os.environ.items() if k in ("PATH", "HOME")})

    result = engine._spawn_process(target, arguments=["1"], environment=env)
    assert result is None or isinstance(result, int)


def test_frida_engine_find_attach_missing_process() -> None:
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)
    if not engine.initialize():
        pytest.skip("Frida device not available")

    pid = engine._find_and_attach_process("r2morph_no_such_process_12345")
    assert pid is None
