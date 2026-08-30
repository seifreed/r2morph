"""Register-file encryption contract for the straight-line engine VM."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import GP_REGISTERS, RSP_INDEX, build_vm_scheme
from r2morph.mutations.code_virtualization_engine_frame import build_frame_layout
from tests.utils.assertions import expect

_EXPECTED_ASM_COUNT_F_XOR_RSI_QWORD_PTR_RSP_LAYOUT_STAT_2 = 2


def test_engine_register_file_uses_runtime_checksum_key() -> None:
    scheme = build_vm_scheme(randomness.Random(20260812))
    layout = build_frame_layout(scheme.frame_size, randomness.Random(scheme.frame_seed))
    asm = _interpreter_asm(0x401000, scheme)
    handler_key = f"qword ptr [rsp+{layout.key_qword_offset}]"
    entry_key = f"qword ptr [rsp + {layout.key_qword_offset}]"
    slot = scheme.slot_perm[next(index for index, name in enumerate(GP_REGISTERS) if name == "rax")]
    rsp_slot = scheme.slot_perm[RSP_INDEX]

    expect(
        all(
            fragment in asm
            for fragment in (
                f"mov rcx, qword ptr [rsp + {slot * 8}]\n"
                f"  xor rcx, qword ptr [rsp + {layout.key_qword_offset}]\n"
                f"  mov qword ptr [rsp + {slot * 8}], rcx",
                f"mov rax, qword ptr [rsp + {slot * 8}]\n  xor rax, {handler_key}",
                f"xor rax, {entry_key}\n  mov qword ptr [rsp + {rsp_slot * 8}], rax",
            )
        )
    )


def test_engine_dispatch_uses_stack_derived_state_key() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    layout = build_frame_layout(scheme.frame_size, randomness.Random(scheme.frame_seed))
    asm = _interpreter_asm(0x401000, scheme)

    expect(layout.state_qword_offset != layout.key_qword_offset)
    expect(not (f"mov qword ptr [rsp + {layout.state_qword_offset}], rax" not in asm))
    expect(
        not (
            asm.count(f"xor rsi, qword ptr [rsp + {layout.state_qword_offset}]")
            < _EXPECTED_ASM_COUNT_F_XOR_RSI_QWORD_PTR_RSP_LAYOUT_STAT_2
        )
    )
