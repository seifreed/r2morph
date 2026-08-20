from pathlib import Path

import pytest

from r2morph.instrumentation.frida_engine import (
    FRIDA_AVAILABLE,
    FridaEngine,
    InstrumentationMode,
)
from tests.utils.assertions import expect

if not FRIDA_AVAILABLE:
    pytest.skip("Frida not available", allow_module_level=True)


def test_frida_engine_unsupported_mode():
    engine = FridaEngine(timeout=1)
    # Even if initialization fails, unsupported mode should return error
    result = engine.instrument_binary(Path("fixtures/dataset/elf_x86_64"), mode=InstrumentationMode.REMOTE)
    expect(not (result.success is not False))
    expect(result.error_message is not None)


def test_frida_engine_initialize_stats():
    engine = FridaEngine(timeout=1)
    if not engine.initialize():
        pytest.skip("Frida device not available")

    stats = engine.get_runtime_statistics()
    expect(not ("processes_instrumented" not in stats))
    engine.cleanup()
