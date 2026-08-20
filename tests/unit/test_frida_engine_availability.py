import pytest

from r2morph.instrumentation.frida_engine import FRIDA_AVAILABLE, FridaEngine
from tests.utils.assertions import expect


def test_frida_engine_availability_behavior():
    if not FRIDA_AVAILABLE:
        with pytest.raises(ImportError):
            FridaEngine(timeout=1)
        return

    engine = FridaEngine(timeout=1)
    expect(engine.timeout == 1)
    expect(engine.stats["processes_instrumented"] == 0)
    # api_calls is a bounded deque (see MAX_RUNTIME_EVENTS), empty at init
    expect(len(engine.api_calls) == 0)

    script = engine._create_api_monitor_script()
    expect(not ("API Call Monitoring Script" not in script))
