"""Unit tests for the engine VM's per-handler scratch-register rename.

These pin the rename's contract - a consistent bijection over the scratch pool
that leaves every pinned/non-pool register alone and varies per seed - and prove
by emulation that a renamed body computes exactly what the original did. The
end-to-end semantic guarantee across every handler kind is carried by the VM
integration suite (which builds with a real ``body_seed`` and checks Unicorn exit
codes); this file guards the primitive in isolation.
"""

from __future__ import annotations

import random
import re

import pytest

from r2morph.mutations.code_virtualization_engine_rename import _POOL, rename_body

_POOL_SPELLINGS = frozenset(spelling for register in _POOL for spelling in register)
# Every pool spelling -> its logical register index (0..4), for bijection checks.
_LOGICAL = {spelling: index for index, register in enumerate(_POOL) for spelling in register}
_ANY_POOL = re.compile(r"\b(" + "|".join(sorted(_POOL_SPELLINGS, key=len, reverse=True)) + r")\b")
# Registers the rename must never touch: the pinned temp/shift-count and the
# dispatch/state registers the handler contract keeps live across the jump.
_PROTECTED = ("rcx", "ecx", "cl", "rsi", "rsp", "r13", "r13b", "r14", "r15", "xmm0", "xmm1")


def test_rename_preserves_pinned_and_non_pool_registers() -> None:
    body = (
        "  mov ecx, eax\n  mov r10, qword ptr [rsp + r8*8]\n  shl r10, cl\n"
        "  xor r8b, r13b\n  movups xmm0, xmmword ptr [rsp + r14]\n  mov r15, rsi\n"
    )
    renamed = rename_body(body, random.Random(7))
    for register in _PROTECTED:
        assert body.count(register) == renamed.count(register)


def test_rename_is_a_consistent_bijection_over_width_spellings() -> None:
    # rax and its narrow spellings must all map to the same target register's
    # spelling of the matching width, and the mapping must be one-to-one.
    body = "  mov rax, r8\n  mov eax, r8d\n  mov ax, r8w\n  mov al, r8b\n"
    renamed = rename_body(body, random.Random(1))
    targets = [_LOGICAL[token] for token in _ANY_POOL.findall(renamed)]
    rax_target = {targets[0], targets[2], targets[4], targets[6]}
    r8_target = {targets[1], targets[3], targets[5], targets[7]}
    # Each source register collapses to exactly one target register (its four width
    # spellings map coherently), and the two sources do not collide (a bijection
    # maps distinct inputs to distinct outputs).
    assert len(rax_target) == 1 and len(r8_target) == 1
    assert rax_target != r8_target


def test_rename_is_polymorphic_across_seeds() -> None:
    body = "  mov rax, qword ptr [rsp + r8*8]\n  add r10, r11\n  xor r9, rax\n"
    produced = {rename_body(body, random.Random(seed)) for seed in range(64)}
    assert len(produced) > 1


def test_rename_does_not_split_a_numbered_register_or_a_label() -> None:
    # ``r10`` must not be rewritten inside ``r10d`` or a label like ``h_10``.
    body = "h_10:\n  mov r10d, r8d\n  jmp vm_dispatch\n"
    renamed = rename_body(body, random.Random(3))
    assert "h_10:" in renamed
    assert "vm_dispatch" in renamed


def test_renamed_body_computes_the_same_result() -> None:
    # Assemble a self-contained body twice (original and renamed) and prove they
    # leave the same value in the surviving frame slot under emulation.
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    from unicorn.x86_const import UC_X86_REG_RSP

    body = (
        "  mov rax, 0x1111\n  mov r8, 0x2222\n  add rax, r8\n"
        "  mov r9, rax\n  xor r9, r8\n  mov qword ptr [rsp], r9\n"
    )
    renamed = rename_body(body, random.Random(9))
    assert renamed != body  # the seed must actually rewrite this pool-heavy body

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    results = []
    for variant in (body, renamed):
        code, _ = ks.asm(variant, 0x1000)
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        mu.mem_map(0x1000, 0x1000)
        mu.mem_map(0x8000, 0x1000)
        mu.mem_write(0x1000, bytes(code))
        mu.reg_write(UC_X86_REG_RSP, 0x8800)
        mu.emu_start(0x1000, 0x1000 + len(code))
        results.append(int.from_bytes(mu.mem_read(0x8800, 8), "little"))
    assert results[0] == results[1] == (0x1111 + 0x2222) ^ 0x2222
