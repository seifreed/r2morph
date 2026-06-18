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

from r2morph.mutations.code_virtualization_engine import _interpreter_asm as _engine_interpreter_asm
from r2morph.mutations.code_virtualization_engine import build_vm_scheme
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm as _region_interpreter_asm

# The decode block's first instruction; one copy per handler tail plus the entry,
# so a threaded interpreter has at least two and a central one has exactly one.
_DECODE_HEAD = "movzx eax, byte ptr [rsi]"


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
