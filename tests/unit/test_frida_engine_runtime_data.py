from pathlib import Path

import pytest

from r2morph.instrumentation.frida_engine import FridaEngine, FRIDA_AVAILABLE

if not FRIDA_AVAILABLE:
    pytest.skip("Frida not available", allow_module_level=True)


@pytest.mark.parametrize("msg_type", ["api_call", "anti_debug", "vm_detection", "timing_check", "memory_operation"])
def test_frida_engine_message_handling(msg_type):
    engine = FridaEngine(timeout=1)

    message = {"type": "send", "payload": {"type": msg_type, "function": "OpenProcess"}}
    engine._on_script_message(message, None)

    stats = engine.get_runtime_statistics()
    assert "api_calls_collected" in stats
    assert "memory_accesses_tracked" in stats
    assert "anti_analysis_events" in stats


def test_frida_engine_script_generation_and_export(tmp_path: Path):
    engine = FridaEngine(timeout=1)

    api_script = engine._create_api_monitor_script()
    anti_script = engine._create_anti_analysis_script()
    mem_script = engine._create_memory_monitor_script()

    assert "API" in api_script
    assert "anti" in anti_script.lower()
    assert "memory" in mem_script.lower()

    export_path = tmp_path / "frida_runtime.json"
    exported = engine.export_runtime_data(export_path)

    assert exported
    assert export_path.exists()


def test_frida_engine_no_session_behaviors():
    engine = FridaEngine(timeout=1)

    loaded = engine.load_script("noop", "console.log('test');")
    assert loaded is False

    dumped = engine.dump_memory_region(0x1000, 16)
    assert dumped is None

    engine.cleanup()
