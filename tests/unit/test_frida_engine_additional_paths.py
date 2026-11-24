from pathlib import Path

from r2morph.instrumentation.frida_engine import (
    FridaEngine,
    InstrumentationMode,
)
from tests.utils.assertions import expect


def test_frida_engine_unsupported_mode():
    engine = FridaEngine(timeout=1)
    # Even if initialization fails, unsupported mode should return error
    result = engine.instrument_binary(Path("fixtures/dataset/elf_x86_64"), mode=InstrumentationMode.REMOTE)
    expect(not (result.success is not False))
    expect(result.error_message is not None)


def test_frida_engine_initialize_stats(frida_device) -> None:
    engine = FridaEngine(timeout=1)

    expect(engine.initialize())
    stats = engine.get_runtime_statistics()
    expect(not ("processes_instrumented" not in stats))
    engine.cleanup()
