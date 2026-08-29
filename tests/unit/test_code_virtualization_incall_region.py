"""
Region extraction of in-function calls: a call whose target lands inside the same
function is lowered to a VM-internal call instead of leaving the region native.

``extract_region`` resolves such a call's target to its item index (like a jmp) and
rewrites it to a ``vcall``; every ``ret`` then becomes a return-aware ``vret``. A call
whose target is not a body instruction boundary is unresolvable and the whole region
stays native, and an out-of-function call keeps the native ``call`` bridge unchanged.

These drive the pure extraction function with hand-built instruction dicts - no r2,
no mocks. Runtime semantic parity is covered by the integration suite.
"""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob
from tests.utils.assertions import expect

_CAVE_VADDR = 0x500000
_INTERNAL_CALL_TARGET = 0x100C


def _insn(addr: int, size: int, itype: str, opcode: str, **extra: object) -> dict[str, object]:
    return {"addr": addr, "size": size, "type": itype, "opcode": opcode, **extra}


def _in_function_call_instructions() -> list[dict[str, object]]:
    """A caller that calls an in-function callee block, each ending in its own ret.

    0x1000 add / 0x1002 call 0x100a / 0x1007 sub (resume) / 0x1009 ret (caller);
    0x100a add (callee body, the call target) / 0x100c ret (callee).
    """
    return [
        _insn(0x1000, 2, "add", "add eax, ebx"),
        _insn(0x1002, 5, "call", "call 0x100a", jump=0x100A),
        _insn(0x1007, 2, "sub", "sub eax, ebx"),
        _insn(0x1009, 1, "ret", "ret"),
        _insn(0x100A, 2, "add", "add ecx, edx"),
        _insn(0x100C, 1, "ret", "ret"),
    ]


def _in_function_indirect_call_instructions() -> list[dict[str, object]]:
    """A register-indirect call whose RIP-relative target is a local block."""
    return [
        _insn(0x1000, 7, "lea", "lea rax, [rip + 0x5]"),
        _insn(0x1007, 2, "rcall", "call rax"),
        _insn(0x1009, 2, "add", "add eax, ebx"),
        _insn(0x100B, 1, "ret", "ret"),
        _insn(_INTERNAL_CALL_TARGET, 2, "add", "add eax, ebx"),
        _insn(0x100E, 1, "ret", "ret"),
    ]


def test_extract_region_lowers_in_function_call_to_vcall() -> None:
    """A direct call whose target is inside the function becomes a vcall item."""
    region = extract_region(_in_function_call_instructions(), randomness.Random(1))
    expect(region is not None)
    expect(any(item[0] == "vcall" for item in region.instructions))


def test_extract_region_leaves_no_native_call_for_an_in_function_call() -> None:
    """The in-function call is fully virtualized, so no native call bridge remains."""
    region = extract_region(_in_function_call_instructions(), randomness.Random(1))
    expect(region is not None)
    expect(not (any(item[0] == "call" for item in region.instructions)))


def test_extract_region_converts_every_ret_to_vret_with_an_in_function_call() -> None:
    """With a vcall present, each ret terminator is the return-aware vret, not exit."""
    region = extract_region(_in_function_call_instructions(), randomness.Random(1))
    expect(region is not None)
    expect(any(item[0] == "vret" for item in region.instructions))
    expect(not (any(item[0] == "exit" for item in region.instructions)))


def test_extract_region_in_function_call_assembles_to_real_bytes() -> None:
    """The lowered region builds a full interpreter blob end to end."""
    region = extract_region(_in_function_call_instructions(), randomness.Random(1))
    expect(region is not None)
    scheme = build_region_scheme(region, randomness.Random(1))
    expect(build_region_blob(region, _CAVE_VADDR, scheme) is not None)


def test_extract_region_rejects_in_function_call_to_non_instruction_boundary() -> None:
    """A call into the middle of an instruction is unresolvable, so the region is native."""
    insns = _in_function_call_instructions()
    insns[1] = _insn(0x1002, 5, "call", "call 0x100b", jump=0x100B)  # 0x100b is mid-instruction
    expect(not (extract_region(insns, randomness.Random(1)) is not None))


def test_extract_region_keeps_out_of_function_call_as_native_bridge() -> None:
    """A call outside the function span keeps the native call and plain exit items."""
    insns = _in_function_call_instructions()
    insns[1] = _insn(0x1002, 5, "call", "call 0x9000", jump=0x9000)  # out of function span
    region = extract_region(insns, randomness.Random(1))
    expect(region is not None)
    expect(any(item[0] == "call" for item in region.instructions))
    expect(not (any(item[0] in ("vcall", "vret") for item in region.instructions)))


def test_extract_region_virtualizes_static_local_indirect_call() -> None:
    """A statically proven local indirect target gets a virtual return path."""
    region = extract_region(_in_function_indirect_call_instructions(), randomness.Random(1))
    expect(region is not None)
    expect(region.has_internal_indirect_call)
    expect(_INTERNAL_CALL_TARGET in region.target_map)
    expect(any(item[0] == "vret" for item in region.instructions))


def test_extract_region_keeps_unproven_indirect_call_native() -> None:
    """An indirect call without a local target proof keeps the native ABI path."""
    instructions = [
        _insn(0x1000, 2, "rcall", "call rax"),
        _insn(0x1002, 1, "ret", "ret"),
    ]
    region = extract_region(instructions, randomness.Random(1))
    expect(region is not None)
    expect(not region.has_internal_indirect_call)
    expect(region.target_map == {})
    expect(not (any(item[0] == "vret" for item in region.instructions)))


def test_extract_region_static_local_indirect_call_assembles() -> None:
    """The local indirect-call route produces a valid interpreter blob."""
    region = extract_region(_in_function_indirect_call_instructions(), randomness.Random(1))
    expect(region is not None)
    scheme = build_region_scheme(region, randomness.Random(1))
    expect(build_region_blob(region, _CAVE_VADDR, scheme) is not None)
