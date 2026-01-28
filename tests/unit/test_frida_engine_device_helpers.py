import pytest

from r2morph.instrumentation.frida_engine import FridaEngine


def test_frida_engine_find_attach_process():
    try:
        engine = FridaEngine(timeout=0)
    except ImportError:
        pytest.skip("Frida not available")

    if not engine.initialize():
        pytest.skip("Frida device not available")

    pid = engine._find_and_attach_process("definitely_not_running_process")
    assert pid is None
