from pathlib import Path

import pytest

from r2morph.instrumentation.frida_engine import FRIDA_AVAILABLE, FridaEngine
from tests.utils.assertions import expect

if not FRIDA_AVAILABLE:
    pytest.skip("Frida not available", allow_module_level=True)


@pytest.mark.parametrize("msg_type", ["api_call", "anti_debug", "vm_detection", "timing_check", "memory_operation"])
def test_frida_engine_message_handling(msg_type):
    engine = FridaEngine(timeout=1)

    message = {"type": "send", "payload": {"type": msg_type, "function": "OpenProcess"}}
    engine._on_script_message(message, None)

    stats = engine.get_runtime_statistics()
    expect(not ("api_calls_collected" not in stats))
    expect(not ("memory_accesses_tracked" not in stats))
    expect(not ("anti_analysis_events" not in stats))


def test_frida_engine_script_generation_and_export(tmp_path: Path):
    engine = FridaEngine(timeout=1)

    api_script = engine._create_api_monitor_script()
    anti_script = engine._create_anti_analysis_script()
    mem_script = engine._create_memory_monitor_script()

    expect(not ("API" not in api_script))
    expect(not ("anti" not in anti_script.lower()))
    expect(not ("memory" not in mem_script.lower()))

    export_path = tmp_path / "frida_runtime.json"
    exported = engine.export_runtime_data(export_path)

    expect(exported)
    expect(export_path.exists())


def test_frida_engine_no_session_behaviors():
    engine = FridaEngine(timeout=1)

    loaded = engine.load_script("noop", "console.log('test');")
    expect(not (loaded is not False))

    dumped = engine.dump_memory_region(0x1000, 16)
    expect(not (dumped is not None))

    engine.cleanup()
