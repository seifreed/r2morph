"""Unit contracts for capability-specific virtualization diagnostics."""

from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_apply import _unwind_metadata_name
from tests.utils.assertions import expect


class _SectionsBinary:
    def __init__(self, names: list[str]) -> None:
        self._sections = [{"name": name} for name in names]

    def get_sections(self) -> list[dict[str, str]]:
        return self._sections


class _TerminalSyscallBinary:
    class _Disassembler:
        @staticmethod
        def cmdj(_command: str) -> dict[str, list[dict[str, str]]]:
            return {"ops": [{"type": "syscall", "addr": 0x1000}]}

    r2 = _Disassembler()


def test_terminal_syscall_is_preserved_as_region_exit() -> None:
    pass_instance = CodeVirtualizationPass(config={})

    expect(pass_instance._find_first_unvirtualizable_instruction(_TerminalSyscallBinary(), {"addr": 0x1000}) is None)


def test_eh_frame_only_is_not_an_exception_table() -> None:
    expect(_unwind_metadata_name(_SectionsBinary([".eh_frame"])) is None)


def test_exception_table_is_rejected_before_virtualization() -> None:
    expect(_unwind_metadata_name(_SectionsBinary([".gcc_except_table"])) == ".gcc_except_table")


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
