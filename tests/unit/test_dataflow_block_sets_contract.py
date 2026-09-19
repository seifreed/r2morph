from __future__ import annotations

from r2morph.analysis.dataflow_block_sets import compute_block_def, compute_block_use
from tests.utils.assertions import expect


def test_dataflow_block_sets_track_use_and_def() -> None:
    instructions = [
        {"disasm": "mov eax, ebx", "type": "mov"},
        {"disasm": "add ecx, eax", "type": "add"},
        {"disasm": "ret", "type": "ret"},
    ]

    expect(compute_block_def(instructions) == {("eax", 32), ("ecx", 32), ("rflags", 64), ("rsp", 64)})
    expect(compute_block_use(instructions) == {("ebx", 32), ("ecx", 32), ("memory", 0), ("rsp", 64)})


def test_dataflow_block_sets_branch_reads_status_flags() -> None:
    instructions = [{"disasm": "jne 0x2000", "type": "cjmp"}]

    expect(compute_block_use(instructions) == {("rflags", 64)})


def test_dataflow_block_sets_arithmetic_defines_status_flags() -> None:
    instructions = [{"disasm": "add eax, ebx", "type": "add"}]

    expect(compute_block_def(instructions) == {("eax", 32), ("rflags", 64)})


def test_dataflow_block_sets_read_modify_write_uses_destination() -> None:
    instructions = [{"disasm": "add eax, ebx", "type": "add"}]

    expect(compute_block_use(instructions) == {("eax", 32), ("ebx", 32)})


def test_dataflow_block_sets_store_uses_address_register() -> None:
    instructions = [{"disasm": "mov [rax], ebx", "type": "mov"}]

    expect(compute_block_use(instructions) == {("rax", 64), ("ebx", 32)})


def test_dataflow_block_sets_varargs_call_reads_sysv_argument_state() -> None:
    instructions = [{"disasm": "call rax", "type": "icall"}]

    used = compute_block_use(instructions)

    expect({("rax", 64), ("rdi", 64), ("xmm0", 128)}.issubset(used))


def test_dataflow_block_sets_call_defines_caller_saved_state() -> None:
    instructions = [{"disasm": "call rax", "type": "icall"}]

    defined = compute_block_def(instructions)

    expect({("rax", 64), ("r11", 64), ("xmm15", 128)}.issubset(defined))


def test_dataflow_block_sets_track_implicit_x86_64_stack_pointer_effects() -> None:
    instructions = [
        {"disasm": "push rbp", "type": "push"},
        {"disasm": "call rax", "type": "icall"},
        {"disasm": "pop rbp", "type": "pop"},
    ]

    expect(("rsp", 64) in compute_block_use(instructions) and ("rsp", 64) in compute_block_def(instructions))


def test_dataflow_block_sets_track_implicit_x86_32_stack_pointer_effects() -> None:
    instructions = [{"disasm": "push ebp", "type": "push"}, {"disasm": "ret", "type": "ret"}]

    expect(("esp", 32) in compute_block_use(instructions, abi="cdecl_32"))


def test_dataflow_block_sets_track_leave_stack_pointer_effects() -> None:
    instructions = [{"disasm": "leave", "type": "leave"}]

    expect(
        compute_block_use(instructions) == {("rbp", 64), ("memory", 0)}
        and compute_block_def(instructions) == {("rbp", 64), ("rsp", 64)}
    )


def test_dataflow_block_sets_track_enter_stack_frame_effects() -> None:
    instructions = [{"disasm": "enter 0x20, 0", "type": "enter"}]

    expect(
        compute_block_use(instructions) == {("rbp", 64), ("rsp", 64), ("memory", 0)}
        and compute_block_def(instructions) == {("rbp", 64), ("rsp", 64), ("memory", 0)}
    )
