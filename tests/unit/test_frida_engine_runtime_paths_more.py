from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.instrumentation import frida_engine


def test_frida_engine_runtime_collection(tmp_path: Path) -> None:
    if not frida_engine.FRIDA_AVAILABLE:
        with pytest.raises(ImportError):
            frida_engine.FridaEngine()
        return

    engine = frida_engine.FridaEngine()
    assert "apis_to_monitor" in engine._create_api_monitor_script()
    assert "anti" in engine._create_anti_analysis_script().lower()
    assert "memory" in engine._create_memory_monitor_script().lower()

    engine._on_script_message({"type": "send", "payload": {"type": "api_call", "function": "open"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "anti_debug", "technique": "timing"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "memory_operation", "address": 1}}, None)
    engine._on_script_message({"type": "error", "description": "boom"}, None)

    stats = engine.get_runtime_statistics()
    assert stats["api_calls_intercepted"] >= 1
    assert stats["api_calls_collected"] == 1
    assert stats["anti_analysis_events"] == 1
    assert stats["memory_accesses_tracked"] == 1

    output_path = tmp_path / "frida_runtime.json"
    assert engine.export_runtime_data(output_path) is True
    assert output_path.exists()
