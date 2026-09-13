"""Unit contracts for capability-specific virtualization diagnostics."""

from typing import Any

from r2morph.analysis.exception_models import ExceptionAction, ExceptionFrame, LandingPad, LsdaTemplate
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_apply import (
    _empty_result,
    _field_counts,
    _function_has_unproven_unwind_metadata,
    _transform_unsupported_function,
    _unwind_blocking_instruction,
    _unwind_metadata_name,
)
from r2morph.mutations.code_virtualization_region import (
    extract_region,
    region_preserves_unwind_contract,
    region_supports_unwind_contract,
)
from r2morph.mutations.code_virtualization_region_models import Region
from tests.utils.assertions import expect

_EXPECTED_DIAGNOSTIC_OPCODE_CHARS = 96
_EXPECTED_DIAGNOSTIC_INSTRUCTION_SIZE = 5


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


class _FarReturnBinary:
    class _Disassembler:
        @staticmethod
        def cmdj(_command: str) -> dict[str, list[dict[str, str | int]]]:
            return {"ops": [{"type": "ret", "opcode": "retfq", "addr": 0x1000, "size": 1}]}

    r2 = _Disassembler()


class _StackAdjustReturnBinary:
    class _Disassembler:
        @staticmethod
        def cmdj(_command: str) -> dict[str, list[dict[str, str | int]]]:
            return {"ops": [{"type": "ret", "opcode": "ret 0x10", "addr": 0x1000, "size": 3}]}

    r2 = _Disassembler()


class _RecordingPass:
    reject_partial_virtualization = False

    def __init__(self) -> None:
        self.diagnostics: list[dict[str, Any]] = []

    def _record_diagnostic(
        self,
        records: list[dict[str, Any]],
        _func: dict[str, Any],
        _instruction: dict[str, Any] | None,
        diagnostic: tuple[str, str, str],
    ) -> None:
        record = {"severity": diagnostic[0], "capability": diagnostic[1], "reason": diagnostic[2]}
        records.append(record)
        self.diagnostics.append(record)

    def _record_unsupported_function(
        self,
        _records: list[dict[str, Any]],
        _func: dict[str, Any],
        _instruction: dict[str, Any] | None,
        _reason_prefix: str = "",
    ) -> None:
        raise AssertionError("unwind-aware fallback must not use the legacy partial path")


def test_partial_virtualization_is_rejected_by_default() -> None:
    expect(CodeVirtualizationPass(config={}).reject_partial_virtualization)


def test_partial_virtualization_can_be_enabled_for_regression_reproduction() -> None:
    expect(not CodeVirtualizationPass(config={"reject_partial_virtualization": False}).reject_partial_virtualization)


def test_virtualization_result_exposes_diagnostic_counts() -> None:
    records = [
        {"severity": "error", "capability": "calls"},
        {"severity": "warning", "capability": "memory_operands"},
        {"severity": "error", "capability": "calls"},
        {"capability": "calls"},
    ]
    empty = _empty_result(None)

    expect(
        _field_counts(records, "severity") == {"error": 2, "warning": 1}
        and _field_counts(records, "capability") == {"calls": 3, "memory_operands": 1}
        and empty["unsupported_function_capabilities"] == {}
        and empty["unsupported_function_severities"] == {}
        and empty["partial_virtualization_capabilities"] == {}
        and empty["partial_virtualization_severities"] == {}
    )


def test_unsupported_record_includes_bounded_instruction_context() -> None:
    record = CodeVirtualizationPass._unsupported_record(
        {"addr": 0x401000},
        {
            "addr": 0x401004,
            "type": "call",
            "opcode": "call " + "x" * 200,
            "size": _EXPECTED_DIAGNOSTIC_INSTRUCTION_SIZE,
        },
        "calls",
        "call semantics were not proven",
        "error",
    )

    expect(
        record["instruction_type"] == "call"
        and record["instruction_mnemonic"] == "call"
        and str(record["instruction_opcode"]).startswith("call ")
        and len(str(record["instruction_opcode"])) == _EXPECTED_DIAGNOSTIC_OPCODE_CHARS
        and record["instruction_size"] == _EXPECTED_DIAGNOSTIC_INSTRUCTION_SIZE
    )


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


def test_far_return_is_not_treated_as_ordinary_region_exit() -> None:
    pass_instance = CodeVirtualizationPass(config={})

    instruction = pass_instance._find_first_unvirtualizable_instruction(_FarReturnBinary(), {"addr": 0x1000})

    expect(instruction == {"type": "ret", "opcode": "retfq", "addr": 0x1000, "size": 1})


def test_stack_adjusting_return_is_not_treated_as_ordinary_region_exit() -> None:
    pass_instance = CodeVirtualizationPass(config={})

    instruction = pass_instance._find_first_unvirtualizable_instruction(_StackAdjustReturnBinary(), {"addr": 0x1000})

    expect(instruction == {"type": "ret", "opcode": "ret 0x10", "addr": 0x1000, "size": 3})


def test_rt_sigreturn_does_not_virtualize_unreachable_tail() -> None:
    instructions = [
        {"type": "mov", "opcode": "mov eax, 15", "addr": 0x1000, "size": 5},
        {"type": "syscall", "opcode": "syscall", "addr": 0x1005, "size": 2},
        {"type": "mov", "opcode": "mov edi, 42", "addr": 0x1007, "size": 5},
        {"type": "ret", "opcode": "ret", "addr": 0x100C, "size": 1},
    ]

    region = extract_region(instructions)

    expect(region is not None and region.body_ranges == [(0x1000, 5)])


def test_empty_eh_frame_is_not_unwind_metadata() -> None:
    expect(_unwind_metadata_name(_SectionsBinary([".eh_frame"], size=0)) is None)


def test_populated_eh_frame_is_unwind_metadata() -> None:
    expect(_unwind_metadata_name(_SectionsBinary([".eh_frame"], size=16)) == ".eh_frame")


def test_exception_table_is_rejected_before_virtualization() -> None:
    expect(_unwind_metadata_name(_SectionsBinary([".gcc_except_table"])) == ".gcc_except_table")


def test_parsed_landing_pad_frame_fails_closed_without_lsda_remap() -> None:
    frame = ExceptionFrame(
        function_start=0x401000,
        function_end=0x401050,
        landing_pads=[LandingPad(0x401030, 8, ExceptionAction.CATCH)],
    )

    expect(_function_has_unproven_unwind_metadata(".gcc_except_table", 0x401000, {0x401000: frame}))


def test_call_bearing_landing_pad_frame_fails_closed_without_lsda_remap() -> None:
    frame = ExceptionFrame(
        function_start=0x401000,
        function_end=0x401050,
        landing_pads=[LandingPad(0x401030, 8, ExceptionAction.CATCH)],
    )

    expect(_function_has_unproven_unwind_metadata(".gcc_except_table", 0x401000, {0x401000: frame}))


def test_call_bearing_frame_without_lsda_is_safe_for_vm_unwinding() -> None:
    frame = ExceptionFrame(function_start=0x401000, function_end=0x401050)

    expect(not _function_has_unproven_unwind_metadata(".eh_frame", 0x401000, {0x401000: frame}))


def test_unwind_frame_lookup_accepts_function_address_inside_frame_range() -> None:
    frame = ExceptionFrame(function_start=0x401000, function_end=0x401050)

    expect(not _function_has_unproven_unwind_metadata(".gcc_except_table", 0x401020, {0x401000: frame}))


def test_unmapped_ordinary_eh_frame_is_not_an_unwind_failure() -> None:
    frame = ExceptionFrame(function_start=0x401000, function_end=0x401050)

    expect(not _function_has_unproven_unwind_metadata(".eh_frame", 0x402000, {0x401000: frame}))


def test_unavailable_unwind_frames_fail_closed() -> None:
    expect(_function_has_unproven_unwind_metadata(".gcc_except_table", 0x401000, None))


def test_partial_virtualization_with_unwind_frame_is_rejected() -> None:
    pass_instance = _RecordingPass()
    records: tuple[list[dict[str, Any]], list[dict[str, Any]]] = ([], [])
    outcome = _transform_unsupported_function(
        pass_instance,
        None,
        {"addr": 0x401000},
        ({"addr": 0x401010}, ExceptionFrame(function_start=0x401000, function_end=0x401050)),
        records,
    )

    expect(
        outcome["skipped"] == 1
        and outcome["unsupported"] == 1
        and records[0][0]["capability"] == "exceptions_and_unwinding"
        and pass_instance.diagnostics[0]["reason"]
        == "partial virtualization has no unwind metadata for the injected VM run"
    )


def test_unwind_region_is_safe_when_landing_pad_and_call_site_are_disjoint() -> None:
    frame = ExceptionFrame(
        function_start=0x401000,
        function_end=0x401080,
        lsda_address=0x402000,
        landing_pads=[
            LandingPad(
                0x401060,
                8,
                ExceptionAction.CATCH,
                metadata={"call_site_start": 0x401050, "call_site_end": 0x401058},
            )
        ],
    )
    region = Region([], 0, 0, set(), [(0x401000, 0x30)])

    expect(region_preserves_unwind_contract(region, frame))


def test_unwind_region_is_rejected_when_protected_call_site_overlaps() -> None:
    frame = ExceptionFrame(
        function_start=0x401000,
        function_end=0x401080,
        lsda_address=0x402000,
        landing_pads=[
            LandingPad(
                0x401060,
                8,
                ExceptionAction.CATCH,
                metadata={"call_site_start": 0x401020, "call_site_end": 0x401028},
            )
        ],
    )
    region = Region([], 0, 0, set(), [(0x401000, 0x30)])

    expect(not region_preserves_unwind_contract(region, frame))


def test_unwind_region_supports_remapped_protected_call_site() -> None:
    frame = ExceptionFrame(
        function_start=0x401000,
        function_end=0x401080,
        personality=0x401090,
        lsda_address=0x402000,
        lsda_template=LsdaTemplate(0xFF, 0xFF, None, 8, bytes((0x01, 0x00))),
        landing_pads=[
            LandingPad(
                0x401060,
                8,
                ExceptionAction.CATCH,
                metadata={"call_site_start": 0x401020, "call_site_end": 0x401028, "action_index": 1},
            )
        ],
    )
    region = Region(
        [],
        0,
        0,
        set(),
        [(0x401000, 0x30)],
        call_site_items=((0x401020, 0x401028, 0),),
    )

    expect(region_supports_unwind_contract(region, frame))


def test_unwind_diagnostic_points_to_call_site() -> None:
    frame = ExceptionFrame(
        function_start=0x401000,
        function_end=0x401050,
        landing_pads=[LandingPad(0x401030, 8, ExceptionAction.CATCH, metadata={"call_site_start": 0x401020})],
    )

    expect(_unwind_blocking_instruction(frame, 0x401000) == {"addr": 0x401020})


def test_tls_instruction_reports_thread_local_storage_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "mov", "opcode": "mov rax, qword [fs:0x28]"}
    )

    expect(capability == "thread_local_storage")


def test_tls_base_instruction_reports_thread_local_storage_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "wrfsbase rax"}
    )

    expect(capability == "thread_local_storage")


def test_swapgs_instruction_reports_thread_local_storage_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "swapgs"}
    )

    expect(capability == "thread_local_storage")


def test_tls_segment_register_reports_thread_local_storage_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "mov", "opcode": "mov ax, fs"}
    )

    expect(capability == "thread_local_storage")


def test_load_fs_far_pointer_reports_thread_local_storage_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "load", "opcode": "lfs eax, [rax]"}
    )

    expect(capability == "thread_local_storage")


def test_load_gs_far_pointer_reports_thread_local_storage_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "load", "opcode": "lgs eax, [rax]"}
    )

    expect(capability == "thread_local_storage")


def test_locked_instruction_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "lock", "opcode": "lock add qword [rax], 1"}
    )

    expect(capability == "thread_synchronization")


def test_memory_xchg_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "mov", "opcode": "xchg qword [rax], rbx"}
    )

    expect(capability == "thread_synchronization")


def test_memory_xadd_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "xadd dword [rax], ebx"}
    )

    expect(capability == "thread_synchronization")


def test_memory_cmpxchg_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "cmpxchg16b [rax]"}
    )

    expect(capability == "thread_synchronization")


def test_transactional_lock_prefix_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "xacquire lock cmpxchg dword [rax], ebx"}
    )

    expect(capability == "thread_synchronization")


def test_transactional_release_prefix_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "xrelease xadd dword [rax], ebx"}
    )

    expect(capability == "thread_synchronization")


def test_implicit_string_memory_instruction_reports_memory_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "cmp", "opcode": "repnz scasb"}
    )

    expect(capability == "memory_operands")


def test_memory_fence_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "sync", "opcode": "mfence"}
    )

    expect(capability == "thread_synchronization")


def test_pause_instruction_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "pause"}
    )

    expect(capability == "thread_synchronization")


def test_mwait_instruction_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "mwait"}
    )

    expect(capability == "thread_synchronization")


def test_user_wait_instruction_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "umwait eax"}
    )

    expect(capability == "thread_synchronization")


def test_transaction_instruction_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "cjmp", "opcode": "xbegin 0x401020"}
    )

    expect(capability == "thread_synchronization")


def test_transaction_suspend_tracking_instruction_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "xsusldtrk"}
    )

    expect(capability == "thread_synchronization")


def test_transaction_resume_tracking_instruction_reports_thread_synchronization_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "xresldtrk"}
    )

    expect(capability == "thread_synchronization")


def test_syscall_instruction_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "syscall", "opcode": "syscall"}
    )

    expect(capability == "signals_and_system_calls")


def test_syscall_return_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "syscall", "opcode": "sysretq"}
    )

    expect(capability == "signals_and_system_calls")


def test_interrupt_return_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "iret", "opcode": "iretq"}
    )

    expect(capability == "signals_and_system_calls")


def test_user_interrupt_return_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "uiret"}
    )

    expect(capability == "signals_and_system_calls")


def test_user_interrupt_send_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "senduipi rax"}
    )

    expect(capability == "signals_and_system_calls")


def test_trap_instruction_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "trap", "opcode": "ud2"})

    expect(capability == "signals_and_system_calls")


def test_overflow_trap_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "trap", "opcode": "into"})

    expect(capability == "signals_and_system_calls")


def test_undefined_instruction_reports_signals_and_system_calls_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "trap", "opcode": "ud1"})

    expect(capability == "signals_and_system_calls")


def test_missing_opcode_reports_instruction_semantics_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "other"})

    expect(capability == "instruction_semantics")


def test_far_jump_instruction_reports_computed_control_flow_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "ljmp 0x33:0x401000"}
    )

    expect(capability == "computed_control_flow")


def test_indirect_jump_opcode_reports_computed_control_flow_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "jmp qword [rax]"}
    )

    expect(capability == "computed_control_flow")


def test_register_indirect_jump_opcode_reports_computed_control_flow_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "jmp rax"}
    )

    expect(capability == "computed_control_flow")


def test_notrack_indirect_jump_opcode_reports_computed_control_flow_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "notrack jmp qword [rax]"}
    )

    expect(capability == "computed_control_flow")


def test_bnd_indirect_jump_opcode_reports_computed_control_flow_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "bnd jmp qword [rax]"}
    )

    expect(capability == "computed_control_flow")


def test_indirect_call_instruction_reports_call_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "icall", "opcode": "qword [rax]"}
    )

    expect(capability == "calls")


def test_direct_call_instruction_reports_call_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "call", "opcode": "call 0x401000"}
    )

    expect(capability == "calls")


def test_notrack_indirect_call_opcode_reports_call_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "notrack call qword [rax]"}
    )

    expect(capability == "calls")


def test_bnd_indirect_call_opcode_reports_call_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "bnd call qword [rax]"}
    )

    expect(capability == "calls")


def test_far_call_instruction_reports_call_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "lcall 0x33:0x401000"}
    )

    expect(capability == "calls")


def test_stack_frame_instruction_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "push", "opcode": "enter 0x20, 0x0"}
    )

    expect(capability == "stack_and_abi")


def test_stack_flag_instruction_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "push", "opcode": "pushfq"}
    )

    expect(capability == "stack_and_abi")


def test_popcnt_instruction_is_not_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "popcnt eax, ebx"}
    )

    expect(capability == "instruction_semantics")


def test_direction_flag_instruction_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "other", "opcode": "std"})

    expect(capability == "stack_and_abi")


def test_carry_flag_instruction_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "other", "opcode": "stc"})

    expect(capability == "stack_and_abi")


def test_complement_carry_flag_instruction_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "other", "opcode": "cmc"})

    expect(capability == "stack_and_abi")


def test_load_flags_instruction_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "lahf"}
    )

    expect(capability == "stack_and_abi")


def test_store_flags_instruction_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "sahf"}
    )

    expect(capability == "stack_and_abi")


def test_shadow_stack_instruction_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "rstorssp qword [rax]"}
    )

    expect(capability == "stack_and_abi")


def test_far_return_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "ret", "opcode": "retfq"})

    expect(capability == "stack_and_abi")


def test_stack_adjusting_return_reports_stack_abi_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "ret", "opcode": "ret 0x10"}
    )

    expect(capability == "stack_and_abi")


def test_indirect_branch_tracking_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "endbr64"}
    )

    expect(capability == "cpu_environment")


def test_cpu_environment_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "rdtsc"}
    )

    expect(capability == "cpu_environment")


def test_processor_id_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "rdpid eax"}
    )

    expect(capability == "cpu_environment")


def test_processor_trace_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "ptwrite rax"}
    )

    expect(capability == "cpu_environment")


def test_port_string_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "outsb"}
    )

    expect(capability == "cpu_environment")


def test_repeated_port_string_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "rep outsb"}
    )

    expect(capability == "cpu_environment")


def test_entropy_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "rdrand eax"}
    )

    expect(capability == "cpu_environment")


def test_msr_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "rdmsr"}
    )

    expect(capability == "cpu_environment")


def test_memory_protection_key_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "wrpkru"}
    )

    expect(capability == "cpu_environment")


def test_bounds_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "bndcl bnd0, [rax]"}
    )

    expect(capability == "cpu_environment")


def test_virtual_machine_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "vmcall"}
    )

    expect(capability == "cpu_environment")


def test_virtual_machine_function_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "vmfunc"}
    )

    expect(capability == "cpu_environment")


def test_enclave_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "enclu"}
    )

    expect(capability == "cpu_environment")


def test_measured_launch_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "getsec"}
    )

    expect(capability == "cpu_environment")


def test_system_management_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "other", "opcode": "rsm"})

    expect(capability == "cpu_environment")


def test_privileged_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "other", "opcode": "hlt"})

    expect(capability == "cpu_environment")


def test_control_register_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "mov", "opcode": "mov rax, cr3"}
    )

    expect(capability == "cpu_environment")


def test_cache_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "clflush [rax]"}
    )

    expect(capability == "cpu_environment")


def test_cache_zero_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "clzero [rax]"}
    )

    expect(capability == "cpu_environment")


def test_repeated_cache_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "rep clflush [rax]"}
    )

    expect(capability == "cpu_environment")


def test_platform_config_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "pconfig"}
    )

    expect(capability == "cpu_environment")


def test_cache_writeback_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "wbnoinvd"}
    )

    expect(capability == "cpu_environment")


def test_direct_store_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "movdir64b rdi, [rsi]"}
    )

    expect(capability == "cpu_environment")


def test_device_queue_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "enqcmd rdi, [rsi]"}
    )

    expect(capability == "cpu_environment")


def test_descriptor_table_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "sgdt [rsp]"}
    )

    expect(capability == "cpu_environment")


def test_segment_access_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "lar eax, ax"}
    )

    expect(capability == "cpu_environment")


def test_data_segment_register_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "mov", "opcode": "mov ds, ax"}
    )

    expect(capability == "cpu_environment")


def test_page_invalidation_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "invpcid rax, [rsp]"}
    )

    expect(capability == "cpu_environment")


def test_machine_status_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "lmsw ax"}
    )

    expect(capability == "cpu_environment")


def test_access_control_instruction_reports_cpu_environment_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "other", "opcode": "stac"}
    )

    expect(capability == "cpu_environment")


def test_simd_memory_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "mov", "opcode": "vmovdqu ymm0, ymmword [rax]"}
    )

    expect(capability == "floating_point_and_simd")


def test_simd_state_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "simd", "opcode": "xsave [rsp]"}
    )

    expect(capability == "floating_point_and_simd")


def test_simd_state_clear_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "simd", "opcode": "vzeroupper"}
    )

    expect(capability == "floating_point_and_simd")


def test_simd_control_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "simd", "opcode": "ldmxcsr [rsp]"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_state_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "frstor [rsp]"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_memory_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "fld qword [rax]"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_arithmetic_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "fadd st0, st1"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_integer_arithmetic_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "fiadd dword [rax]"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_integer_compare_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "ficom word [rax]"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_conditional_move_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "fcmovb st0, st1"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_stack_pointer_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "fincstp"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_bcd_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "fbld tword [rax]"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_extract_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "fxtract"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_wait_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic({"type": "fpu", "opcode": "fwait"})

    expect(capability == "floating_point_and_simd")


def test_mmx_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "simd", "opcode": "paddb mm0, mm7"}
    )

    expect(capability == "floating_point_and_simd")


def test_mmx_state_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "simd", "opcode": "femms"}
    )

    expect(capability == "floating_point_and_simd")


def test_avx512_mask_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "simd", "opcode": "kortestw k1, k7"}
    )

    expect(capability == "floating_point_and_simd")


def test_amx_tile_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "simd", "opcode": "tdpbf16ps tmm0, tmm1, tmm2"}
    )

    expect(capability == "floating_point_and_simd")


def test_amx_tile_config_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "simd", "opcode": "ldtilecfg [rsp]"}
    )

    expect(capability == "floating_point_and_simd")


def test_x87_stack_instruction_reports_fp_simd_capability() -> None:
    capability, _reason = CodeVirtualizationPass._unsupported_instruction_diagnostic(
        {"type": "fpu", "opcode": "fadd st0, st7"}
    )

    expect(capability == "floating_point_and_simd")
