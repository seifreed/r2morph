from r2morph.mutations.stack_strings_helpers import (
    EncodingScheme,
    StackStringOptions,
    _format_plain_stack_byte,
    _xor_rolling_decode_loop_x64,
    add_shift_encode,
    find_printable_strings,
    generate_stack_string_x64,
    xor_bytes,
    xor_rolling,
)
from tests.utils.assertions import expect


def test_stack_string_helpers_cover_the_core_encoding_paths() -> None:
    expect(EncodingScheme.XOR_ROLLING == "xor_rolling")
    expect(xor_bytes(b"AB", 16) == b"QR")
    encoded, final_key = xor_rolling(b"AB", 0x42)
    expect(encoded != b"AB")
    expect(isinstance(final_key, int))
    expect(add_shift_encode(b"AB", 1) == b"BC")
    expect(find_printable_strings(b"\x00ABC\x00", 3))
    expect(_format_plain_stack_byte(0, 65, "rsp") == "    mov byte [rsp+0], 'A'")
    expect(_xor_rolling_decode_loop_x64(2, 17, 34)[0] == "    ; Decode rolling XOR string")
    asm, junk = generate_stack_string_x64(b"AB\x00", StackStringOptions(encoding=EncodingScheme.PLAIN))
    expect(not ("sub rsp" not in asm))
    expect(isinstance(junk, list))
