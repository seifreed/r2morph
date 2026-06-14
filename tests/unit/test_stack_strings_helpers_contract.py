from r2morph.mutations.stack_strings_helpers import (
    EncodingScheme,
    _format_plain_stack_byte,
    _xor_rolling_decode_loop_x64,
    add_shift_encode,
    find_printable_strings,
    generate_stack_string_x64,
    xor_bytes,
    xor_rolling,
)


def test_stack_string_helpers_cover_the_core_encoding_paths() -> None:
    assert EncodingScheme.XOR_ROLLING == "xor_rolling"
    assert xor_bytes(b"AB", 0x10) == b"QR"
    encoded, final_key = xor_rolling(b"AB", 0x42)
    assert encoded != b"AB"
    assert isinstance(final_key, int)
    assert add_shift_encode(b"AB", 1) == b"BC"
    assert find_printable_strings(b"\x00ABC\x00", 3)
    assert _format_plain_stack_byte(0, 65, "rsp") == "    mov byte [rsp+0], 'A'"
    assert _xor_rolling_decode_loop_x64(2, 0x11, 0x22)[0] == "    ; Decode rolling XOR string"
    asm, junk = generate_stack_string_x64(b"AB\x00", encoding=EncodingScheme.PLAIN)
    assert "sub rsp" in asm
    assert isinstance(junk, list)
