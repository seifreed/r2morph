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

Threaded dispatch is the only shape either VM emits. A central dispatcher ending
in a compare/branch ladder over the opcode indices was removed: a decompiler
rebuilds such a ladder into a plain ``switch`` and recovers the whole
opcode-to-handler mapping, while the offset table here is XOR-encrypted at
runtime. The ladder-absence tests below pin that floor over a seed sweep, so no
build can regress to the reconstructible shape.
"""

from __future__ import annotations

import re
from typing import Any

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_dispatch import bytecode_position_mask, decode_block
from r2morph.mutations.code_virtualization_engine import (
    GP_REGISTERS,
    build_vm_scheme,
    gp_save_order,
)
from r2morph.mutations.code_virtualization_engine import (
    _interpreter_asm as _engine_interpreter_asm,
)
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm as _region_interpreter_asm
from r2morph.mutations.code_virtualization_region_nesting import _decode_block as _nested_decode_block
from tests.utils.assertions import expect

_EXPECTED_ASM_COUNT_F_XOR_RSI_QWORD_PTR_RSP_STATE_OFFSE_2 = 2
_EXPECTED_ASM_COUNT_XOR_R13_QWORD_PTR_RSP_2 = 2
_EXPECTED_ASM_COUNT_XOR_R15_QWORD_PTR_RSP_2 = 2
_EXPECTED_ASM_COUNT_XOR_RSI_QWORD_PTR_RSP_2 = 2
_BYTE_VALUE_COUNT = 256


# The decode block's first instruction; one copy per handler tail plus the entry,
# so a threaded interpreter has at least two and a central one has exactly one.
_DECODE_HEAD = "movzx eax, byte ptr [rsi]"

# Enough seeds that any surviving per-build shape choice would show up.
_SEED_SWEEP = range(16)

# Representative decode pieces (the three opcode XORs deliberately differ in byte
# length, so a length-invariant result proves shuffling does not change size).
_OPCODE_XORS = ["  xor al, 0x52\n", "  xor al, r13b\n", "  xor al, byte ptr [rsp+0x88]\n"]
_TABLE_XORS = ["  xor eax, 0x1234\n", "  movzx ecx, byte ptr [rsp+0x88]\n  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n"]


def _without_transfer(assembly: str) -> frozenset[str]:
    return frozenset(line for line in assembly.splitlines() if line.strip() not in {"jmp rax", "push rax", "ret"})


def _decode(seed: int) -> str:
    return decode_block(
        opcode_xors=_OPCODE_XORS,
        bounds="  cmp al, 0xd\n  jae vm_exit\n",
        table_load="  lea r14, [rip+vm_table]\n  mov eax, dword ptr [r14+rax*4]\n",
        table_xors=_TABLE_XORS,
        rng=randomness.Random(seed),
    )


def _tiny_region() -> Any:
    instructions = [
        {"addr": 0x1000, "type": "mov", "opcode": "mov edi, 0x2a", "size": 5, "jump": -1},
        {"addr": 0x1005, "type": "mov", "opcode": "mov eax, 0x3c", "size": 5, "jump": -1},
        {"addr": 0x100A, "type": "swi", "opcode": "syscall", "size": 2, "jump": -1},
    ]
    region = extract_region(instructions)
    expect(region is not None)
    return region


def _region_asm(seed: int) -> str:
    region = _tiny_region()
    return _region_interpreter_asm(region, build_region_scheme(region, randomness.Random(seed)))


def _engine_asm(seed: int) -> str:
    return _engine_interpreter_asm(0x1000, build_vm_scheme(randomness.Random(seed)))


def _engine_spill_order(seed: int) -> tuple[str, ...]:
    return tuple(re.findall(r"mov qword ptr \[rsp \+ \d+\], (\w+)", _engine_asm(seed))[:15])


def _frame_size(asm: str) -> str:
    match = re.search(r"vm_entry:\n  sub rsp, (\d+)", asm)
    expect(match is not None)
    return match.group(1)


def test_bytecode_position_mask_has_one_progressive_cycle() -> None:
    masks = tuple(bytecode_position_mask(position) for position in range(_BYTE_VALUE_COUNT))
    expect(len(set(masks)) == _BYTE_VALUE_COUNT and masks != tuple(range(_BYTE_VALUE_COUNT)))


def test_region_interpreter_has_no_central_dispatch_label() -> None:
    asm = _region_asm(0)
    expect("vm_dispatch:" not in asm)
    expect("jmp vm_dispatch" not in asm)


def test_region_interpreter_inlines_the_decode_per_handler() -> None:
    # Threaded: the decode head appears at the entry and at every handler tail, so
    # there is more than one copy - a central dispatcher would have exactly one.
    expect(not (_region_asm(0).count(_DECODE_HEAD) <= 1))


def test_region_dispatch_encodes_live_virtual_state_at_indirect_jump() -> None:
    asm = _region_asm(0)
    state_offset = build_region_scheme(_tiny_region(), randomness.Random(0)).state_offset
    expect(
        not (
            asm.count(f"xor rsi, qword ptr [rsp+{state_offset}]")
            < _EXPECTED_ASM_COUNT_F_XOR_RSI_QWORD_PTR_RSP_STATE_OFFSE_2
        )
    )


def test_nested_dispatch_encodes_live_virtual_state_at_indirect_jump() -> None:
    state_offset = 0x240
    asm = _nested_decode_block(randomness.Random(0), state_offset)
    expect(asm.count(f"xor rsi, qword ptr [rsp+{state_offset}]") == 1)


def test_region_interpreter_enters_bootstrap_before_antidebug_probe() -> None:
    asm = _region_asm(0)

    first_transfer = min(position for marker in ("jmp rax", "push rax") if (position := asm.find(marker)) >= 0)
    expect(not (first_transfer >= min(asm.index("rdtsc"), asm.index("syscall"))))


def test_engine_interpreter_has_no_central_dispatch_label() -> None:
    # The threaded shape inlines the decode, so no handler jumps to a shared block.
    asm = _engine_asm(0)
    expect("vm_dispatch:" not in asm)
    expect("jmp vm_dispatch" not in asm)


def test_engine_interpreter_inlines_the_decode_per_handler() -> None:
    expect(not (_engine_asm(0).count(_DECODE_HEAD) <= 1))


def test_engine_integrity_defers_full_checksum_until_bootstrap_ready() -> None:
    asm = _engine_asm(0)

    expect(not ("entry_chk_loop:" not in asm))
    expect(not ("ready_chk_loop:" not in asm))
    expect(not (asm.index("entry_chk_loop:") >= asm.index("vm_bootstrap:")))
    expect(not (asm.index("ready_chk_loop:") <= asm.index("vm_bootstrap:")))


def test_engine_dispatch_encodes_live_virtual_state_at_indirect_jump() -> None:
    asm = _engine_asm(0)
    expect(not (asm.count("xor rsi, qword ptr [rsp +") < _EXPECTED_ASM_COUNT_XOR_RSI_QWORD_PTR_RSP_2))
    expect(not (asm.count("xor r15, qword ptr [rsp +") < _EXPECTED_ASM_COUNT_XOR_R15_QWORD_PTR_RSP_2))
    expect(not (asm.count("xor r13, qword ptr [rsp +") < _EXPECTED_ASM_COUNT_XOR_R13_QWORD_PTR_RSP_2))


def test_engine_interpreter_enters_bootstrap_before_antidebug_probe() -> None:
    asm = _engine_asm(0)

    first_transfer = min(position for marker in ("jmp rax", "push rax") if (position := asm.find(marker)) >= 0)
    expect(not (first_transfer >= min(asm.index("rdtsc"), asm.index("syscall"))))


def test_engine_interpreter_save_order_varies_across_builds() -> None:
    seeds = range(10)
    orders = {_engine_spill_order(seed) for seed in seeds}

    expect(not (len(orders) <= 1))
    expect(
        all(
            _engine_spill_order(seed)
            == tuple(
                GP_REGISTERS[index]
                for index in gp_save_order(build_vm_scheme(randomness.Random(seed)).junk_seed ^ 0x51A7E)
            )
            for seed in seeds
        )
    )


def test_engine_interpreter_frame_size_varies_across_builds() -> None:
    expect(not (len({_frame_size(_engine_asm(seed)) for seed in range(10)}) <= 1))


def test_region_interpreter_frame_size_varies_across_builds() -> None:
    expect(not (len({_frame_size(_region_asm(seed)) for seed in range(10)}) <= 1))


def test_engine_interpreter_never_emits_a_compare_branch_ladder() -> None:
    # No seed may produce the removed switch shape: its tell is a direct
    # ``je h_<index>`` leaf per opcode, which a decompiler rebuilds into a switch.
    expect(not ([seed for seed in _SEED_SWEEP if "je h_" in _engine_asm(seed)]))


def test_region_interpreter_never_emits_a_compare_branch_ladder() -> None:
    # Same floor for the region VM, whose handler labels are capital ``H_<index>``.
    expect(not ([seed for seed in _SEED_SWEEP if "je H_" in _region_asm(seed)]))


def test_engine_interpreter_always_dispatches_through_the_offset_table() -> None:
    # Every build routes through the XOR-encrypted offset table and its computed
    # goto, so no build ships a statically resolvable handler mapping.
    expect(
        all(
            "vm_table" in _engine_asm(seed) and ("jmp rax" in _engine_asm(seed) or "push rax" in _engine_asm(seed))
            for seed in _SEED_SWEEP
        )
    )


def test_region_interpreter_always_dispatches_through_the_offset_table() -> None:
    expect(
        all(
            "vm_table" in _region_asm(seed) and ("jmp rax" in _region_asm(seed) or "push rax" in _region_asm(seed))
            for seed in _SEED_SWEEP
        )
    )


def test_dispatch_transfer_form_varies_across_seeds() -> None:
    forms = {"stack" if "push rax" in _decode(seed) else "jump" for seed in range(20)}

    expect(forms == {"jump", "stack"})


def test_decode_block_is_polymorphic_across_seeds() -> None:
    # The inlined copies must not be one repeated byte-signature: shuffling the
    # order-independent XOR groups yields more than one distinct layout. With many
    # seeds over 6*2 orderings, all-identical is effectively impossible, so this is
    # deterministic in practice. Exit-code tests pass with or without the shuffle,
    # so the polymorphism property needs its own assertion.
    expect(not (len({_decode(seed) for seed in range(20)}) <= 1))


def test_decode_block_shuffle_preserves_common_instructions() -> None:
    # Shuffling and transfer polymorphism keep the decode body identical; only
    # instruction order and the final indirect-transfer form vary.
    variants = [_decode(seed) for seed in range(20)]
    expect(len({_without_transfer(v) for v in variants}) == 1)
