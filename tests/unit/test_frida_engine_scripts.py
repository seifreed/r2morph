from pathlib import Path

import pytest

from r2morph.instrumentation.frida_engine import FridaEngine, FRIDA_AVAILABLE


def test_frida_script_generation_and_export(tmp_path):
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)

    api_script = engine._create_api_monitor_script()
    anti_script = engine._create_anti_analysis_script()
    mem_script = engine._create_memory_monitor_script()

    assert "API Call Monitoring" in api_script
    assert "Anti-Analysis" in anti_script
    assert "Memory Access" in mem_script

    assert engine.load_script("noop", "") is False

    engine._on_script_message({"type": "send", "payload": {"type": "api_call", "function": "CreateFile"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "anti_debug"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "memory_operation"}}, None)

    stats = engine.get_runtime_statistics()
    assert stats["api_calls_collected"] >= 1

    output_path = tmp_path / "runtime.json"
    assert engine.export_runtime_data(output_path) is True
    assert output_path.exists()


def test_frida_initialize_and_lookup():
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)
    assert engine.initialize() in {True, False}

    if engine.device is not None:
        assert engine._find_and_attach_process("process_that_should_not_exist") is None

    assert engine.dump_memory_region(0x0, 4) is None
    engine.cleanup()
