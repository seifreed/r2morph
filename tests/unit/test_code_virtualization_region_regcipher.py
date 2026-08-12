"""Register-file cipher scope contract."""

from r2morph.mutations.code_virtualization_region_regcipher import cipher_register_slots


def test_cipher_register_slots_transforms_only_register_file() -> None:
    source = (
        "  mov rax, qword ptr [rsp+r8*8]\n"
        "  mov qword ptr [rsp+r8*8], r10\n"
        "  mov r9, qword ptr [rsp+56]\n"
        "  mov rax, qword ptr [rsp+128]\n"
        "  mov qword ptr [rsp+r9+0x288], rax"
    )

    result = cipher_register_slots(source)

    assert all(
        fragment in result
        for fragment in (
            "mov rax, qword ptr [rsp+r8*8]\n  xor rax, qword ptr [rsp+520]",
            "xor r10, qword ptr [rsp+520]\n  mov qword ptr [rsp+r8*8], r10",
            "mov r9, qword ptr [rsp+56]\n  xor r9, qword ptr [rsp+520]",
            "mov rax, qword ptr [rsp+128]\n  mov qword ptr [rsp+r9+0x288], rax",
        )
    )
