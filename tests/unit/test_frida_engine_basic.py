import pytest

from r2morph.instrumentation.frida_engine import FridaEngine, InstrumentationMode, FRIDA_AVAILABLE


def test_frida_engine_initialization_and_unsupported_mode():
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)
    result = engine.instrument_binary("/bin/ls", mode=InstrumentationMode.REMOTE)

    assert result.success is False
    assert result.error_message is not None
