from pathlib import Path

from r2morph.instrumentation.frida_engine import FridaEngine, InstrumentationMode
from tests.utils.assertions import expect


def test_frida_engine_spawn_failure(tmp_path: Path, frida_device):
    engine = FridaEngine(timeout=0)
    expect(engine.initialize())
    frida_device.spawn.side_effect = OSError("spawn unavailable")

    fake_binary = tmp_path / "not_exec"
    fake_binary.write_text("not executable")

    result = engine.instrument_binary(fake_binary, mode=InstrumentationMode.SPAWN)
    expect(not (result.success is not False))
    expect(result.error_message is not None)


def test_frida_engine_attach_failure(frida_device):
    engine = FridaEngine(timeout=0)
    expect(engine.initialize())

    result = engine.instrument_binary(Path("/nonexistent/process"), mode=InstrumentationMode.ATTACH)
    expect(not (result.success is not False))
    expect(result.error_message is not None)
