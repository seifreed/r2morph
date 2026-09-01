"""Register-file cipher scope contract."""

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine import VirtualizedOp
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from r2morph.mutations.code_virtualization_region_regcipher import cipher_register_slots
from tests.utils.assertions import expect

_REGISTER_FILE_RELOADS = 15


def test_cipher_register_slots_transforms_only_register_file() -> None:
    source = (
        "  mov rax, qword ptr [rsp+r8*8]\n"
        "  mov qword ptr [rsp+r8*8], r10\n"
        "  mov r9, qword ptr [rsp+56]\n"
        "  mov r10, qword ptr [rsp+144]\n"
        "  mov rax, qword ptr [rsp+128]\n"
        "  mov qword ptr [rsp+r9+0x288], rax"
    )

    result = cipher_register_slots(source, frozenset({56, 144}))

    expect(
        all(
            fragment in result
            for fragment in (
                "mov rax, qword ptr [rsp+r8*8]\n  xor rax, qword ptr [rsp+520]",
                "xor r10, qword ptr [rsp+520]\n  mov qword ptr [rsp+r8*8], r10",
                "mov r9, qword ptr [rsp+56]\n  xor r9, qword ptr [rsp+520]",
                "mov r10, qword ptr [rsp+144]\n  xor r10, qword ptr [rsp+520]",
                "mov rax, qword ptr [rsp+128]\n  mov qword ptr [rsp+r9+0x288], rax",
            )
        )
    )


def test_region_exit_decrypts_register_file_before_native_return() -> None:
    operation = VirtualizedOp("mov", 0, 1, False, 64)
    items = [("op", operation), ("exit", 0x2000)]
    region = Region(
        items,
        0x2000,
        0x1000,
        {key for item in items if (key := _op_key(item)) is not None},
        [(0x1000, 3)],
    )
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(7)))
    exit_block = assembly.split("vm_exit:\n", 1)[1].split("vm_table:", 1)[0]

    expect(exit_block.count("xor ") == _REGISTER_FILE_RELOADS)
