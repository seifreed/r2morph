from types import SimpleNamespace
from unittest.mock import Mock, patch

from r2morph.validation.semantic_symbolic import (
    create_symbolic_state,
    default_observables,
    run_symbolic_validation,
)


def test_default_observables_matches_word_size() -> None:
    assert default_observables(64)[0] == "rax"
    assert default_observables(32)[0] == "eax"


def test_create_symbolic_state_builds_expected_registers() -> None:
    state = SimpleNamespace(regs=SimpleNamespace(rsp=None, rbp=None, rax=None))
    project = SimpleNamespace(factory=SimpleNamespace(blank_state=Mock(return_value=state)))

    with patch(
        "r2morph.validation.semantic_symbolic.claripy",
        SimpleNamespace(
            BVV=lambda value, bits: ("BVV", value, bits),
            BVS=lambda name, size: ("BVS", name, size),
        ),
    ):
        created = create_symbolic_state(project, 0x1000, 64, ["rax", "eflags"])

    assert created is state
    assert state.regs.rsp == ("BVV", 0x100000, 64)
    assert state.regs.rbp == ("BVV", 0x100000, 64)
    assert state.regs.rax == ("BVS", "rax_1000", 64)


@patch("r2morph.validation.semantic_symbolic.ANGR_AVAILABLE", False)
def test_run_symbolic_validation_skips_when_angr_missing() -> None:
    result = SimpleNamespace(region=SimpleNamespace(start_address=0x1000), symbolic_status="not_requested")
    run_symbolic_validation(Mock(), result, None)
    assert result.symbolic_status == "angr_unavailable"
