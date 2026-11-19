import importlib.util

import pytest

from r2morph.adapters.angr_import import import_angr_modules
from tests.utils.assertions import expect


def test_angr_import_uses_claripy_compatible_with_real_state() -> None:
    if importlib.util.find_spec("angr") is None:
        pytest.skip("angr is an optional dependency and is not installed")
    modules = import_angr_modules(claripy=True)
    if not modules.available or modules.angr is None or modules.claripy is None:
        raise AssertionError("angr and its Claripy module must be available")

    project = modules.angr.load_shellcode(b"\x90\xc3", arch="amd64")
    state = project.factory.blank_state()
    symbolic_value = modules.claripy.BVS("compatible_memory_value", 64)
    state.memory.store(0x1000, symbolic_value, endness=state.arch.memory_endness)
    loaded_value = state.memory.load(0x1000, 8, endness=state.arch.memory_endness)

    expect(state.solver.is_true(loaded_value == symbolic_value))
