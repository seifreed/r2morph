from pathlib import Path
import subprocess
import time

import pytest

from r2morph.instrumentation.frida_engine import FridaEngine, InstrumentationMode, FRIDA_AVAILABLE


def test_frida_engine_spawn_success_path():
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)
    if not engine.initialize():
        pytest.skip("Frida device not available")

    target = Path("/bin/sleep")
    if not target.exists():
        pytest.skip("sleep binary not available")

    proc = subprocess.Popen([str(target), "3"])
    try:
        time.sleep(0.1)
        result = engine.instrument_binary(target, mode=InstrumentationMode.ATTACH)
        if result.success:
            assert result.process_id > 0
            assert result.instrumentation_time >= 0
            assert isinstance(result.api_calls_captured, int)
        else:
            assert result.error_message is not None
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        engine.cleanup()
