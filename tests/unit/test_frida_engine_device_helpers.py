from r2morph.instrumentation.frida_engine import FridaEngine
from tests.utils.assertions import expect


def test_frida_engine_find_attach_process(frida_device):
    engine = FridaEngine(timeout=0)
    expect(engine.initialize())

    pid = engine._find_and_attach_process("definitely_not_running_process")
    expect(not (pid is not None))
