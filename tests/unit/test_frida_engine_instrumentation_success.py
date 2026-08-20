import os
import time
from pathlib import Path

import pytest

from r2morph.instrumentation.frida_engine import FRIDA_AVAILABLE, FridaEngine, InstrumentationMode
from tests.utils.assertions import expect


def test_frida_engine_spawn_success_path():
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)
    if not engine.initialize():
        pytest.skip("Frida device not available")

    target = Path("/bin/sleep")
    if not target.exists():
        pytest.skip("sleep binary not available")

    process_id = os.posix_spawn(str(target), [str(target), "3"], os.environ)
    try:
        time.sleep(0.1)
        result = engine.instrument_binary(target, mode=InstrumentationMode.ATTACH)
        if result.success:
            expect(not (result.process_id <= 0))
            expect(not (result.instrumentation_time < 0))
            expect(isinstance(result.api_calls_captured, int))
        else:
            expect(result.error_message is not None)
    finally:
        os.kill(process_id, 15)
        os.waitpid(process_id, 0)
        engine.cleanup()
