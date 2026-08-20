from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.instrumentation import frida_engine
from tests.utils.assertions import expect


def test_frida_engine_runtime_collection(tmp_path: Path) -> None:
    if not frida_engine.FRIDA_AVAILABLE:
        with pytest.raises(ImportError):
            frida_engine.FridaEngine()
        return

    engine = frida_engine.FridaEngine()
    expect(not ("apis_to_monitor" not in engine._create_api_monitor_script()))
    expect(not ("anti" not in engine._create_anti_analysis_script().lower()))
    expect(not ("memory" not in engine._create_memory_monitor_script().lower()))

    engine._on_script_message({"type": "send", "payload": {"type": "api_call", "function": "open"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "anti_debug", "technique": "timing"}}, None)
    engine._on_script_message({"type": "send", "payload": {"type": "memory_operation", "address": 1}}, None)
    engine._on_script_message({"type": "error", "description": "boom"}, None)

    stats = engine.get_runtime_statistics()
    expect(not (stats["api_calls_intercepted"] < 1))
    expect(stats["api_calls_collected"] == 1)
    expect(stats["anti_analysis_events"] == 1)
    expect(stats["memory_accesses_tracked"] == 1)

    output_path = tmp_path / "frida_runtime.json"
    expect(not (engine.export_runtime_data(output_path) is not True))
    expect(output_path.exists())
