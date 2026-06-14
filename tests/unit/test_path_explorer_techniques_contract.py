import importlib.util

import pytest

if importlib.util.find_spec("angr") is None:
    pytest.skip("angr not available", allow_module_level=True)

from r2morph.analysis.symbolic.path_explorer_techniques import (
    OpaquePredicateDetectionTechnique,
    VMHandlerDetectionTechnique,
)


class _FakeSolver:
    def symbolic(self, _value: object) -> bool:
        return True


class _FakeRegs:
    rip = object()


class _FakeMemReads:
    hardcopy = [1, 2, 3, 4, 5, 6]


class _FakeHistory:
    jump_kind = "Ijk_Boring"
    depth = 3
    mem_reads = _FakeMemReads()
    addr = 0x401000
    jumpkind = "Ijk_Conditional"


class _FakeState:
    solver = _FakeSolver()
    regs = _FakeRegs()
    history = _FakeHistory()


class _FakeSimgr:
    def __init__(self) -> None:
        self.stashes = {"active": [_FakeState()]}


def test_path_explorer_techniques_score_and_track_branch_outcomes() -> None:
    vm = VMHandlerDetectionTechnique()
    score = vm._score_vm_likelihood(_FakeState())
    assert score > 0

    simgr = _FakeSimgr()
    vm.step(simgr)
    assert len(simgr.stashes["active"]) == 1

    opaque = OpaquePredicateDetectionTechnique()
    opaque_state = _FakeState()
    opaque_state.history.jump_kind = "Ijk_Conditional"
    for _ in range(5):
        opaque._track_branch_outcomes(opaque_state)

    assert 0x401000 in opaque.opaque_candidates
    opaque.step(simgr)
    assert simgr.stashes["active"]
