from r2morph.instrumentation.frida_engine import FridaEngine


def test_frida_engine_on_script_message_types():
    engine = FridaEngine(timeout=0)

    engine._on_script_message({"type": "send", "payload": {"type": "api_call", "function": "OpenProcess"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "anti_debug"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "vm_detection"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "timing_check"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "memory_operation"}}, None)

    stats = engine.get_runtime_statistics()
    assert stats["api_calls_collected"] >= 1
    assert stats["anti_analysis_events"] >= 1
    assert stats["memory_accesses_tracked"] >= 1
