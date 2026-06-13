"""Characterization of the x64 stack-string junk interleaving (§5 oracle).

Pins the exact junk-interleaved assembly under a fixed RNG seed so the
junk-machinery extraction stays behavior-preserving (same table, same order
of random draws).
"""

import random

from r2morph.mutations.stack_strings import EncodingScheme, generate_stack_string_x64


def test_x64_junk_interleaving_exact_under_seed():
    random.seed(0)
    asm, junk = generate_stack_string_x64(
        b"Hi", EncodingScheme.PLAIN, interleave_junk=True, junk_probability=1.0
    )

    assert junk == ["xor r15, r15", "push rax"]
    assert asm == (
        "    ; Stack string (plain): 2 bytes\n"
        "    sub rsp, 18\n"
        "    mov byte [rsp+0], 'H'\n"
        "    xor r15, r15  ; junk\n"
        "    mov byte [rsp+1], 'i'\n"
        "    push rax\npop rax  ; junk"
    )
