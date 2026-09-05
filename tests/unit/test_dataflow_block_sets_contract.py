from __future__ import annotations

from r2morph.analysis.dataflow_block_sets import compute_block_def, compute_block_use
from tests.utils.assertions import expect


def test_dataflow_block_sets_track_use_and_def() -> None:
    instructions = [
        {"disasm": "mov eax, ebx", "type": "mov"},
        {"disasm": "add ecx, eax", "type": "add"},
        {"disasm": "ret", "type": "ret"},
    ]

    expect(compute_block_def(instructions) == {("eax", 32), ("ecx", 32), ("rflags", 64)})
    expect(compute_block_use(instructions) == {("ebx", 32), ("memory", 0)})


def test_dataflow_block_sets_branch_reads_status_flags() -> None:
    instructions = [{"disasm": "jne 0x2000", "type": "cjmp"}]

    expect(compute_block_use(instructions) == {("rflags", 64)})


def test_dataflow_block_sets_arithmetic_defines_status_flags() -> None:
    instructions = [{"disasm": "add eax, ebx", "type": "add"}]

    expect(compute_block_def(instructions) == {("eax", 32), ("rflags", 64)})


def test_dataflow_block_sets_varargs_call_reads_sysv_argument_state() -> None:
    instructions = [{"disasm": "call rax", "type": "icall"}]

    used = compute_block_use(instructions)

    expect({("rax", 64), ("rdi", 64), ("xmm0", 128)}.issubset(used))


def test_dataflow_block_sets_call_defines_caller_saved_state() -> None:
    instructions = [{"disasm": "call rax", "type": "icall"}]

    defined = compute_block_def(instructions)

    expect({("rax", 64), ("r11", 64), ("xmm15", 128)}.issubset(defined))
