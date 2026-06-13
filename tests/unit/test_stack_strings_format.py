"""Characterization of _format_plain_stack_byte (§5 oracle).

Pins every branch of the plain byte formatter shared by the x64/x86 stack
string generators: NUL, printable char, quote/backslash escape, and
non-printable hex.
"""

from r2morph.mutations.stack_strings import _format_plain_stack_byte


def test_nul_byte():
    assert _format_plain_stack_byte(5, 0, "rsp") == "    mov byte [rsp+5], 0"


def test_printable_char():
    assert _format_plain_stack_byte(0, ord("A"), "rsp") == "    mov byte [rsp+0], 'A'"


def test_single_quote_is_escaped_numerically():
    assert _format_plain_stack_byte(1, ord("'"), "esp") == "    mov byte [esp+1], 39  ; '''"


def test_backslash_is_escaped_numerically():
    assert _format_plain_stack_byte(2, ord("\\"), "rsp") == "    mov byte [rsp+2], 92  ; '\\'"


def test_non_printable_byte_as_hex():
    assert _format_plain_stack_byte(3, 0xFF, "esp") == "    mov byte [esp+3], 0xFF"


def test_boundary_space_is_hex():
    # 32 (space) is not in (32, 128), so it falls through to hex
    assert _format_plain_stack_byte(4, 32, "rsp") == "    mov byte [rsp+4], 0x20"
