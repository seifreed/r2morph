import pytest

from r2morph.instrumentation.frida_engine import FRIDA_AVAILABLE, FridaEngine


def test_frida_engine_availability_behavior():
    if not FRIDA_AVAILABLE:
        with pytest.raises(ImportError):
            FridaEngine(timeout=1)
        return

    engine = FridaEngine(timeout=1)
    assert engine.timeout == 1
    assert engine.stats["processes_instrumented"] == 0
    # api_calls is a bounded deque (see MAX_RUNTIME_EVENTS), empty at init
    assert len(engine.api_calls) == 0

    script = engine._create_api_monitor_script()
    assert "API Call Monitoring Script" in script
