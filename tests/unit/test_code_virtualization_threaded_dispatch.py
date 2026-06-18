"""
Unit tests for direct-threaded dispatch in both virtualization VMs.

A single central dispatch block every handler jumps back to is the defining
structural tell of an intermediate VM: it is the highest in-degree node in the
CFG (which a devirtualizer flags as "the dispatcher") and one fixed instruction
sequence a VM-finder pattern-matches. Threaded dispatch inlines the opcode decode
at the entry and at every handler tail, so each handler decodes the next opcode
itself and jumps straight to the next handler - there is no shared dispatcher
node. These tests pin that property on the real interpreter builders (no mocks,
no binary); the exit-code integration suite proves the threading stays correct,
but those pass with or without threading, so the structural property needs its
own assertion.
"""

from __future__ import annotations

import random
from typing import Any

from r2morph.mutations.code_virtualization_dispatch import decode_block
from r2morph.mutations.code_virtualization_engine import _interpreter_asm as _engine_interpreter_asm
from r2morph.mutations.code_virtualization_engine import build_vm_scheme
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm as _region_interpreter_asm

# The decode block's first instruction; one copy per handler tail plus the entry,
# so a threaded interpreter has at least two and a central one has exactly one.
_DECODE_HEAD = "movzx eax, byte ptr [rsi]"

# Representative decode pieces (the three opcode XORs deliberately differ in byte
# length, so a length-invariant result proves shuffling does not change size).
_OPCODE_XORS = ["  xor al, 0x52\n", "  xor al, r13b\n", "  xor al, byte ptr [rsp+0x88]\n"]
_TABLE_XORS = ["  xor eax, 0x1234\n", "  movzx ecx, byte ptr [rsp+0x88]\n  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n"]


def _decode(seed: int) -> str:
    return decode_block(
        opcode_xors=_OPCODE_XORS,
        bounds="  cmp al, 0xd\n  jae vm_exit\n",
        table_load="  lea r14, [rip+vm_table]\n  mov eax, dword ptr [r14+rax*4]\n",
        table_xors=_TABLE_XORS,
        rng=random.Random(seed),
    )


def _tiny_region() -> Any:
    instructions = [
        {"addr": 0x1000, "type": "mov", "opcode": "mov edi, 0x2a", "size": 5, "jump": -1},
        {"addr": 0x1005, "type": "mov", "opcode": "mov eax, 0x3c", "size": 5, "jump": -1},
        {"addr": 0x100A, "type": "swi", "opcode": "syscall", "size": 2, "jump": -1},
    ]
    region = extract_region(instructions)
    assert region is not None
    return region


def test_region_interpreter_has_no_central_dispatch_label() -> None:
    asm = _region_interpreter_asm(_tiny_region(), build_region_scheme(_tiny_region(), random.Random(0)))
    assert "vm_dispatch:" not in asm
    assert "jmp vm_dispatch" not in asm


def test_region_interpreter_inlines_the_decode_per_handler() -> None:
    # Threaded: the decode head appears at the entry and at every handler tail, so
    # there is more than one copy - a central dispatcher would have exactly one.
    asm = _region_interpreter_asm(_tiny_region(), build_region_scheme(_tiny_region(), random.Random(0)))
    assert asm.count(_DECODE_HEAD) > 1


def test_engine_interpreter_has_no_central_dispatch_label() -> None:
    asm = _engine_interpreter_asm(0x1000, build_vm_scheme(random.Random(0)))
    assert "vm_dispatch:" not in asm
    assert "jmp vm_dispatch" not in asm


def test_engine_interpreter_inlines_the_decode_per_handler() -> None:
    asm = _engine_interpreter_asm(0x1000, build_vm_scheme(random.Random(0)))
    assert asm.count(_DECODE_HEAD) > 1


def test_decode_block_is_polymorphic_across_seeds() -> None:
    # The inlined copies must not be one repeated byte-signature: shuffling the
    # order-independent XOR groups yields more than one distinct layout. With many
    # seeds over 6*2 orderings, all-identical is effectively impossible, so this is
    # deterministic in practice. Exit-code tests pass with or without the shuffle,
    # so the polymorphism property needs its own assertion.
    assert len({_decode(seed) for seed in range(20)}) > 1


def test_decode_block_shuffle_preserves_length_and_instructions() -> None:
    # Shuffling only reorders existing instructions, so every copy is the same byte
    # length (keeping assembled size and the size-vs-depth invariants stable) and
    # carries exactly the same instruction lines - only their order varies.
    variants = [_decode(seed) for seed in range(20)]
    assert len({len(v) for v in variants}) == 1
    assert len({frozenset(v.splitlines()) for v in variants}) == 1
