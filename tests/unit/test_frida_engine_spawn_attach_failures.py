from pathlib import Path

import pytest

from r2morph.instrumentation.frida_engine import FridaEngine, InstrumentationMode


def test_frida_engine_spawn_failure(tmp_path: Path):
    try:
        engine = FridaEngine(timeout=0)
    except ImportError:
        pytest.skip("Frida not available")

    if not engine.initialize():
        pytest.skip("Frida device not available")

    fake_binary = tmp_path / "not_exec"
    fake_binary.write_text("not executable")

    result = engine.instrument_binary(fake_binary, mode=InstrumentationMode.SPAWN)
    assert result.success is False
    assert result.error_message is not None


def test_frida_engine_attach_failure():
    try:
        engine = FridaEngine(timeout=0)
    except ImportError:
        pytest.skip("Frida not available")

    if not engine.initialize():
        pytest.skip("Frida device not available")

    result = engine.instrument_binary(
        Path("/nonexistent/process"), mode=InstrumentationMode.ATTACH
    )
    assert result.success is False
    assert result.error_message is not None
