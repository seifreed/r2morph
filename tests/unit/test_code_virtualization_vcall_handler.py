"""
In-function call/return handlers: a call whose target lands inside the same
function is virtualized entirely inside the VM instead of bridging to native code.

``vcall`` pushes a resume vIP - the address of the item after the call, which lives
inside the appended bytecode - onto the program's relocated stack and re-enters the
VM at the callee's virtualized entry (decoded like a jmp). ``vret`` is the return-
aware ret terminator: it resumes the VM at a pushed resume vIP when the top of the
program stack falls inside the bytecode range ``[r15, r15+bytecode_len)``, and
otherwise returns natively to the real caller. The native body is junk-filled, so
neither ever jumps to the overwritten original code.

These pin the structural contract: the opcode-key and encoded-size naming, that the
interpreter carries the resume-push and the range-discriminated return, and that a
region using them assembles to real bytes. Runtime semantic parity is covered by the
regression/integration suites.
"""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm, build_region_blob
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from tests.utils.assertions import expect

_EXPECTED_ITEM_SIZE_VCALL_2_5 = 5


_CAVE_VADDR = 0x500000
_RET_ADDR = 0x2000


def _incall_region() -> Region:
    """A minimal region: item 0 calls item 2 (the callee body), which returns.

    Item 1 is the caller's own return terminator; item 2 is the callee body (a nop);
    item 3 is the callee's return terminator. Both returns are the return-aware
    ``vret``, as they are once a region contains any in-function call.
    """
    return Region(
        instructions=[("vcall", 2), ("vret", _RET_ADDR), ("nop",), ("vret", _RET_ADDR)],
        exit_vaddr=_RET_ADDR,
        entry_vaddr=0x1000,
        op_keys={"vcall", "vret_8192", "nop"},
        body_ranges=[(0x1000, 5), (0x1005, 1), (0x1006, 1), (0x1007, 1)],
    )


def test_op_key_vcall_maps_to_the_shared_vcall_handler() -> None:
    expect(_op_key(("vcall", 2)) == "vcall")


def test_op_key_vret_is_keyed_per_return_address() -> None:
    expect(_op_key(("vret", _RET_ADDR)) == f"vret_{_RET_ADDR}")


def test_item_size_vcall_is_opcode_plus_four_byte_offset() -> None:
    # Same 5-byte layout as a jmp: the resume vIP is rsi + 5.
    expect(_item_size(("vcall", 2)) == _EXPECTED_ITEM_SIZE_VCALL_2_5)


def test_item_size_vret_is_a_single_opcode_byte() -> None:
    expect(_item_size(("vret", _RET_ADDR)) == 1)


def test_interpreter_emits_the_vcall_resume_computation() -> None:
    """The vcall handler computes the resume vIP as the item after the 5-byte call.

    The scratch registers are renamed per handler instance, so the assertion pins the
    rename-invariant ``[rsi+5]`` resume address rather than a specific register.
    """
    region = _incall_region()
    asm = _interpreter_asm(region, build_region_scheme(region, randomness.Random(7)))
    expect(not ("[rsi+5]" not in asm))


def test_interpreter_emits_the_vret_bytecode_range_discriminator() -> None:
    """The vret handler subtracts the bytecode base and branches on the range check."""
    region = _incall_region()
    asm = _interpreter_asm(region, build_region_scheme(region, randomness.Random(7)))
    expect("sub r11, r15" in asm and "vret_native_" in asm)


def test_incall_region_assembles_to_real_bytes() -> None:
    """A region using vcall and vret assembles cleanly through the full blob build."""
    region = _incall_region()
    scheme = build_region_scheme(region, randomness.Random(7))
    expect(build_region_blob(region, _CAVE_VADDR, scheme) is not None)
