"""
Unit tests for the ``ijmp`` item: the region VM's register-indirect computed jump.

A computed-goto interpreter reaches its handlers through a register-indirect jump
(``jmp reg``) whose target is a runtime value. Lowering it to an ``ijmp`` item is
the load-bearing front-end change for virtualizing dispatch-shaped code. It is
gated off by default so the straight-line region contract keeps rejecting computed
jumps (only the dispatch-region contract opts in), and it is modelled on the
existing register-indirect call (``icall``): a single register slot, no static
target address.

These exercise the pure classification and dispatch-table functions directly with
hand-built instruction dicts - no r2, no mocks.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_engine import GP_REGISTERS
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_models import _op_key


def test_classify_register_indirect_jump_yields_ijmp_when_opted_in() -> None:
    """``jmp reg`` lowers to an ijmp carrying the register's slot index."""
    insn = {"type": "rjmp", "opcode": "jmp rax"}
    assert _classify(insn, allow_computed_jump=True) == ["ijmp", GP_REGISTERS.index("rax")]


def test_classify_register_indirect_jump_rejected_by_default() -> None:
    """Without opt-in, a computed jump stays unsupported - the straight-line contract."""
    assert _classify({"type": "rjmp", "opcode": "jmp rax"}) is None


def test_classify_no_base_memory_indirect_jump_lowered_to_ijmpmemnb() -> None:
    """A no-base memory-indexed computed jump (non-PIE switch dispatch) lowers to an
    ijmpmemnb carrying the index slot, scale shift, and table-base displacement."""
    insn = {"type": "ujmp", "opcode": "jmp qword [rax*8 + 0x2000]"}
    assert _classify(insn, allow_computed_jump=True) == ["ijmpmemnb", 0, 3, 0x2000]


def test_classify_based_memory_indirect_jump_lowered_to_ijmpmem() -> None:
    """A based memory-indexed computed jump lowers to an ijmpmem (base + index)."""
    insn = {"type": "ujmp", "opcode": "jmp qword [rbx + rax*8]"}
    assert _classify(insn, allow_computed_jump=True) == ["ijmpmem", 3, 0, 3, 0]


def test_classify_memory_indirect_jump_requires_opt_in() -> None:
    """Without the dispatch opt-in a memory-indirect computed jump stays native."""
    insn = {"type": "ujmp", "opcode": "jmp qword [rax*8 + 0x2000]"}
    assert _classify(insn, allow_computed_jump=False) is None


def test_classify_indirect_jump_through_rsp_rejected() -> None:
    """rsp is the relocated VM stack pointer, never a virtualizable jump target."""
    assert _classify({"type": "rjmp", "opcode": "jmp rsp"}, allow_computed_jump=True) is None


def test_ijmp_op_key_is_its_own_handler_family() -> None:
    """The ijmp item maps to a distinct handler key for opcode assignment."""
    assert _op_key(("ijmp", 3)) == "ijmp"


def test_ijmp_item_size_matches_indirect_call() -> None:
    """An ijmp encodes as an opcode byte plus a single register-slot byte."""
    assert _item_size(("ijmp", 3)) == 2
