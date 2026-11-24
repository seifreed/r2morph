from pathlib import Path

from r2morph.instrumentation.frida_engine import FridaEngine
from tests.utils.assertions import expect


def test_frida_engine_spawn_with_args_and_env(frida_device) -> None:
    engine = FridaEngine(timeout=1)
    expect(engine.initialize())
    target = Path("unit-test-target")
    env = {"R2MORPH_TEST_ENV": "1"}

    result = engine._spawn_process(target, arguments=["1"], environment=env)
    expect(result == frida_device.spawn.return_value)
    frida_device.spawn.assert_called_once_with([str(target), "1"], env=env)


def test_frida_engine_find_attach_missing_process(frida_device) -> None:
    engine = FridaEngine(timeout=1)
    expect(engine.initialize())

    pid = engine._find_and_attach_process("r2morph_no_such_process_12345")
    expect(not (pid is not None))
