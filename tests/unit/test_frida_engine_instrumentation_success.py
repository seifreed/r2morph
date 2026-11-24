from pathlib import Path
from types import SimpleNamespace

from r2morph.instrumentation.frida_engine import FridaEngine, InstrumentationMode
from tests.utils.assertions import expect

_TEST_PROCESS_ID = 1234


def test_frida_engine_attach_success_path(frida_device):
    frida_device.enumerate_processes.return_value = [SimpleNamespace(name="target", pid=_TEST_PROCESS_ID)]
    engine = FridaEngine(timeout=0)
    expect(engine.initialize())

    result = engine.instrument_binary(Path("target"), mode=InstrumentationMode.ATTACH)

    expect(result.success)
    expect(result.process_id == _TEST_PROCESS_ID)
    expect(result.instrumentation_time >= 0)
    expect(isinstance(result.api_calls_captured, int))
    frida_device.attach.assert_called_once_with(_TEST_PROCESS_ID)
    engine.cleanup()
