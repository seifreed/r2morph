"""Unit contracts for capability-specific virtualization diagnostics."""

from types import SimpleNamespace
from typing import Any

from r2morph.analysis.exception_models import ExceptionAction, ExceptionFrame, LandingPad
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_apply import (
    _function_contains_virtualized_call,
    _function_has_unproven_unwind_metadata,
    _unwind_metadata_name,
)
from r2morph.mutations.code_virtualization_region import extract_region
from tests.utils.assertions import expect


class _SectionsBinary:
    def __init__(self, names: list[str], size: int | None = None) -> None:
        self._sections = [{"name": name, **({"size": size} if size is not None else {})} for name in names]

    def get_sections(self) -> list[dict[str, Any]]:
        return self._sections


class _TerminalSyscallBinary:
    class _Disassembler:
        @staticmethod
        def cmdj(_command: str) -> dict[str, list[dict[str, Any]]]:
            return {"ops": [{"type": "syscall", "addr": 0x1000}]}

    r2 = _Disassembler()


class _NonTerminalSyscallBinary:
    class _Disassembler:
        @staticmethod
        def cmdj(_command: str) -> dict[str, list[dict[str, str | int]]]:
            return {
                "ops": [
                    {"type": "syscall", "addr": 0x1000, "size": 2},
                    {"type": "mov", "opcode": "mov rax, 1", "addr": 0x1002, "size": 7},
                    {"type": "ret", "addr": 0x1009, "size": 1},
                ]
            }

    r2 = _Disassembler()


class _PaddedTerminalSyscallBinary:
    class _Disassembler:
        @staticmethod
        def cmdj(_command: str) -> dict[str, list[dict[str, str | int]]]:
            return {
                "ops": [
                    {"type": "syscall", "opcode": "syscall", "addr": 0x1000, "size": 2},
                    {"type": "trap", "opcode": "int3", "addr": 0x1002, "size": 1},
                ]
            }

    r2 = _Disassembler()


class _CandidateRegionPass:
    virtualize_dispatch = False

    @staticmethod
    def _has_computed_jump(_binary: object, _func: dict[str, int]) -> bool:
        return False

    @staticmethod
    def _find_run(_binary: object, _block: dict[str, int]) -> SimpleNamespace:
        return SimpleNamespace(ops=[])


class _CallOutsideCandidateBinary:
    class _Disassembler:
        @staticmethod
        def cmdj(_command: str) -> dict[str, list[dict[str, str | int]]]:
            return {
                "ops": [
                    {"type": "call", "opcode": "call 0x2000", "jump": 0x2000, "addr": 0x1000, "size": 5},
                    {"type": "invalid", "opcode": "invalid", "addr": 0x1005, "size": 1},
                ]
            }

    r2 = _Disassembler()

    @staticmethod
    def get_basic_blocks(_address: int) -> list[dict[str, int]]:
        return [{"addr": 0x1000}]


class _CallInsideCandidateBinary:
    class _Disassembler:
        @staticmethod
        def cmdj(_command: str) -> dict[str, list[dict[str, str | int]]]:
            return {
                "ops": [
                    {"type": "call", "opcode": "call 0x2000", "jump": 0x2000, "addr": 0x1000, "size": 5},
                    {"type": "ret", "opcode": "ret", "addr": 0x1005, "size": 1},
                ]
            }

    r2 = _Disassembler()

    @staticmethod
    def get_basic_blocks(_address: int) -> list[dict[str, int]]:
        return []


def test_partial_virtualization_is_rejected_by_default() -> None:
    expect(CodeVirtualizationPass(config={}).reject_partial_virtualization)


def test_partial_virtualization_can_be_enabled_for_regression_reproduction() -> None:
    expect(not CodeVirtualizationPass(config={"reject_partial_virtualization": False}).reject_partial_virtualization)


def test_terminal_syscall_is_preserved_as_region_exit() -> None:
    pass_instance = CodeVirtualizationPass(config={})

    expect(pass_instance._find_first_unvirtualizable_instruction(_TerminalSyscallBinary(), {"addr": 0x1000}) is None)


def test_non_terminal_syscall_is_classified_for_native_bridge() -> None:
    pass_instance = CodeVirtualizationPass(config={})

    instruction = pass_instance._find_first_unvirtualizable_instruction(_NonTerminalSyscallBinary(), {"addr": 0x1000})

    expect(instruction is None)


def test_terminal_syscall_with_disassembler_padding_is_preserved_as_region_exit() -> None:
    pass_instance = CodeVirtualizationPass(config={})

    expect(
        pass_instance._find_first_unvirtualizable_instruction(_PaddedTerminalSyscallBinary(), {"addr": 0x1000}) is None
    )


def test_rt_sigreturn_does_not_virtualize_unreachable_tail() -> None:
    instructions = [
        {"type": "mov", "opcode": "mov eax, 15", "addr": 0x1000, "size": 5},
        {"type": "syscall", "opcode": "syscall", "addr": 0x1005, "size": 2},
        {"type": "mov", "opcode": "mov edi, 42", "addr": 0x1007, "size": 5},
        {"type": "ret", "opcode": "ret", "addr": 0x100C, "size": 1},
    ]

    region = extract_region(instructions)

    expect(region is not None and region.body_ranges == [(0x1000, 5)])


def test_unwind_gate_ignores_call_outside_candidate_run() -> None:
    result = _function_contains_virtualized_call(
        _CandidateRegionPass(), _CallOutsideCandidateBinary(), {"addr": 0x1000}
    )

    expect(not result)


def test_unwind_gate_rejects_call_inside_candidate_region() -> None:
    result = _function_contains_virtualized_call(_CandidateRegionPass(), _CallInsideCandidateBinary(), {"addr": 0x1000})

    expect(result)


def test_empty_eh_frame_is_not_unwind_metadata() -> None:
    expect(_unwind_metadata_name(_SectionsBinary([".eh_frame"], size=0)) is None)


def test_populated_eh_frame_is_unwind_metadata() -> None:
    expect(_unwind_metadata_name(_SectionsBinary([".eh_frame"], size=16)) == ".eh_frame")


def test_exception_table_is_rejected_before_virtualization() -> None:
    expect(_unwind_metadata_name(_SectionsBinary([".gcc_except_table"])) == ".gcc_except_table")


def test_parsed_landing_pad_frame_is_safe_for_synchronous_virtualization() -> None:
    frame = ExceptionFrame(
        function_start=0x401000,
        function_end=0x401050,
        landing_pads=[LandingPad(0x401030, 8, ExceptionAction.CATCH)],
    )

    expect(not _function_has_unproven_unwind_metadata(".gcc_except_table", 0x401000, {0x401000: frame}))


def test_call_bearing_landing_pad_frame_fails_closed_without_lsda_remap() -> None:
    frame = ExceptionFrame(
        function_start=0x401000,
        function_end=0x401050,
        landing_pads=[LandingPad(0x401030, 8, ExceptionAction.CATCH)],
    )

    expect(_function_has_unproven_unwind_metadata(".gcc_except_table", 0x401000, {0x401000: frame}, True))


def test_unwind_frame_lookup_accepts_function_address_inside_frame_range() -> None:
    frame = ExceptionFrame(function_start=0x401000, function_end=0x401050)

    expect(not _function_has_unproven_unwind_metadata(".gcc_except_table", 0x401020, {0x401000: frame}))


def test_unavailable_unwind_frames_fail_closed() -> None:
    expect(_function_has_unproven_unwind_metadata(".gcc_except_table", 0x401000, None))


def test_tls_instruction_reports_thread_local_storage_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "mov", "opcode": "mov rax, qword [fs:0x28]"}
    )

    expect(capability == "thread_local_storage")


def test_locked_instruction_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "lock", "opcode": "lock add qword [rax], 1"}
    )

    expect(capability == "thread_synchronization")


def test_syscall_instruction_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "syscall", "opcode": "syscall"}
    )

    expect(capability == "signals_and_system_calls")
