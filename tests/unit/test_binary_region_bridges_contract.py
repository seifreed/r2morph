"""Contract tests for real-binary region bridge helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from r2morph.validation.binary_region_bridges import build_state_pair, validate_binary_paths


def test_validate_binary_paths_returns_paths_for_existing_artifacts(tmp_path: Path) -> None:
    """Existing pre/post artifacts should resolve to concrete paths."""
    previous_binary = tmp_path / "previous.bin"
    current_binary = tmp_path / "current.bin"
    previous_binary.write_bytes(b"\x7fELF")
    current_binary.write_bytes(b"\x7fELF")

    result = validate_binary_paths(SimpleNamespace(path=current_binary), {"previous_binary_path": previous_binary})

    assert result == (previous_binary, current_binary)


def test_build_state_pair_initializes_shared_registers_for_x64() -> None:
    """The helper should seed both states with shared symbolic registers."""

    class FakeRegs:
        def __init__(self) -> None:
            for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"):
                setattr(self, name, None)

    class FakeState:
        def __init__(self) -> None:
            self.regs = FakeRegs()

    class FakeFactory:
        def blank_state(self, *, addr: int, add_options: set[object]) -> FakeState:
            assert addr in {0x401000, 0x401010}
            assert add_options == {"ZERO_FILL_UNCONSTRAINED_MEMORY", "ZERO_FILL_UNCONSTRAINED_REGISTERS"}
            return FakeState()

    class FakeBridge:
        def __init__(self) -> None:
            self.angr_project = SimpleNamespace(factory=FakeFactory())

    class FakeClaripy:
        @staticmethod
        def BVV(value: int, bits: int) -> tuple[str, int, int]:
            return ("BVV", value, bits)

        @staticmethod
        def BVS(name: str, bits: int) -> tuple[str, str, int]:
            return ("BVS", name, bits)

    original_state, mutated_state, compared_registers, stack_reg = build_state_pair(
        FakeBridge(),
        FakeBridge(),
        SimpleNamespace(get_arch_info=lambda: {"bits": 64}),
        FakeClaripy,
        SimpleNamespace(
            ZERO_FILL_UNCONSTRAINED_MEMORY="ZERO_FILL_UNCONSTRAINED_MEMORY",
            ZERO_FILL_UNCONSTRAINED_REGISTERS="ZERO_FILL_UNCONSTRAINED_REGISTERS",
        ),
        0x401000,
        0x401010,
        0x401000,
    )

    assert (
        stack_reg == "rsp"
        and compared_registers == ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]
        and original_state.regs.rsp == ("BVV", 0x100000, 64)
        and mutated_state.regs.rbp == ("BVV", 0x100000, 64)
        and original_state.regs.rax == ("BVS", "rax_401000", 64)
        and mutated_state.regs.rax == ("BVS", "rax_401000", 64)
    )
