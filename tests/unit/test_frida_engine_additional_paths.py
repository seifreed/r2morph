from pathlib import Path

import pytest

from r2morph.instrumentation.frida_engine import (
    FridaEngine,
    InstrumentationMode,
    FRIDA_AVAILABLE,
)

if not FRIDA_AVAILABLE:
    pytest.skip("Frida not available", allow_module_level=True)


def test_frida_engine_unsupported_mode():
    engine = FridaEngine(timeout=1)
    # Even if initialization fails, unsupported mode should return error
    result = engine.instrument_binary(
        Path("dataset/elf_x86_64"), mode=InstrumentationMode.REMOTE
    )
    assert result.success is False
    assert result.error_message is not None


def test_frida_engine_initialize_stats():
    engine = FridaEngine(timeout=1)
    if not engine.initialize():
        pytest.skip("Frida device not available")

    stats = engine.get_runtime_statistics()
    assert "processes_instrumented" in stats
    engine.cleanup()
