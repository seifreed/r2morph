import pytest

from r2morph.instrumentation.frida_engine import FRIDA_AVAILABLE, FridaEngine
from tests.utils.assertions import expect


def test_frida_script_generation_and_export(tmp_path):
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)

    api_script = engine._create_api_monitor_script()
    anti_script = engine._create_anti_analysis_script()
    mem_script = engine._create_memory_monitor_script()

    expect(not ("API Call Monitoring" not in api_script))
    expect(not ("Anti-Analysis" not in anti_script))
    expect(not ("Memory Access" not in mem_script))

    expect(not (engine.load_script("noop", "") is not False))

    engine._on_script_message({"type": "send", "payload": {"type": "api_call", "function": "CreateFile"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "anti_debug"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "memory_operation"}}, None)

    stats = engine.get_runtime_statistics()
    expect(not (stats["api_calls_collected"] < 1))

    output_path = tmp_path / "runtime.json"
    expect(not (engine.export_runtime_data(output_path) is not True))
    expect(output_path.exists())


def test_frida_initialize_and_lookup():
    if not FRIDA_AVAILABLE:
        pytest.skip("Frida not available")

    engine = FridaEngine(timeout=1)
    expect(not (engine.initialize() not in {True, False}))

    expect(
        not (engine.device is not None and engine._find_and_attach_process("process_that_should_not_exist") is not None)
    )

    expect(not (engine.dump_memory_region(0x0, 4) is not None))
    engine.cleanup()
