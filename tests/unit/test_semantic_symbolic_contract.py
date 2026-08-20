from types import SimpleNamespace

import claripy

from r2morph.validation.semantic_symbolic import (
    create_symbolic_state,
    default_observables,
)
from tests.utils.assertions import expect

_EXPECTED_STATE_REGS_RBP_1048576 = 0x100000
_EXPECTED_STATE_REGS_RSP_1048576 = 0x100000


def test_default_observables_matches_word_size() -> None:
    expect(default_observables(64)[0] == "rax")
    expect(default_observables(32)[0] == "eax")


def test_create_symbolic_state_builds_expected_registers() -> None:
    state = SimpleNamespace(regs=SimpleNamespace(rsp=None, rbp=None, rax=None))

    class _Factory:
        def blank_state(self, *, addr: int) -> SimpleNamespace:
            return state

    project = SimpleNamespace(factory=_Factory())
    created = create_symbolic_state(project, 0x1000, 64, ["rax", "eflags"])

    expect(not (created is not state))
    expect(claripy.is_true(state.regs.rsp == _EXPECTED_STATE_REGS_RSP_1048576))
    expect(claripy.is_true(state.regs.rbp == _EXPECTED_STATE_REGS_RBP_1048576))
    expect(next(iter(state.regs.rax.variables)).startswith("rax_1000_"))
