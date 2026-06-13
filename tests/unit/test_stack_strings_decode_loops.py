"""Characterization of the x64 decode-loop builders (§5 oracle).

Pins the exact assembly each builder emits for a fixed label id so the
extraction from generate_stack_string_x64 stays byte-identical.
"""

from r2morph.mutations.stack_strings import (
    _add_shift_decode_loop_x64,
    _xor_rolling_decode_loop_x64,
    _xor_single_decode_loop_x64,
)


def test_xor_single_decode_loop():
    assert _xor_single_decode_loop_x64(4, 0x55, 0xABC) == [
        "    ; Decode XOR'd string",
        "    lea rdi, [rsp]",
        "    mov rcx, 4",
        "    mov dl, 0x55",
        ".decode_loop_abc:",
        "    xor byte [rdi], dl",
        "    inc rdi",
        "    loop .decode_loop_abc",
    ]


def test_xor_rolling_decode_loop():
    assert _xor_rolling_decode_loop_x64(3, 0x7F, 0x10) == [
        "    ; Decode rolling XOR string",
        "    lea rdi, [rsp]",
        "    mov rcx, 3",
        "    mov dl, 0x7F",
        ".decode_loop_10:",
        "    xor byte [rdi], dl",
        "    inc rdi",
        "    imul dl, 7",
        "    inc dl",
        "    and dl, 0xFF",
        "    loop .decode_loop_10",
    ]


def test_add_shift_decode_loop():
    assert _add_shift_decode_loop_x64(5, 3, 0x20) == [
        "    ; Decode ADD-shift'd string",
        "    lea rdi, [rsp]",
        "    mov rcx, 5",
        ".decode_loop_20:",
        "    sub byte [rdi], 3",
        "    inc rdi",
        "    loop .decode_loop_20",
    ]
