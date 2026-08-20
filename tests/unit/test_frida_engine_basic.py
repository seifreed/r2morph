import pytest

from r2morph.instrumentation.frida_engine import FRIDA_AVAILABLE, FridaEngine, InstrumentationMode
from tests.utils.assertions import expect


def test_frida_engine_initialization_and_unsupported_mode():
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)
    result = engine.instrument_binary("/bin/ls", mode=InstrumentationMode.REMOTE)

    expect(not (result.success is not False))
    expect(result.error_message is not None)
