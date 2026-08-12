from types import SimpleNamespace

import claripy

from r2morph.validation.semantic_symbolic import (
    create_symbolic_state,
    default_observables,
)


def test_default_observables_matches_word_size() -> None:
    assert default_observables(64)[0] == "rax"
    assert default_observables(32)[0] == "eax"


def test_create_symbolic_state_builds_expected_registers() -> None:
    state = SimpleNamespace(regs=SimpleNamespace(rsp=None, rbp=None, rax=None))

    class _Factory:
        def blank_state(self, *, addr: int) -> SimpleNamespace:
            return state

    project = SimpleNamespace(factory=_Factory())
    created = create_symbolic_state(project, 0x1000, 64, ["rax", "eflags"])

    assert created is state
    assert claripy.is_true(state.regs.rsp == 0x100000)
    assert claripy.is_true(state.regs.rbp == 0x100000)
    assert next(iter(state.regs.rax.variables)).startswith("rax_1000_")
