"""Shared data types and handler-key naming for region virtualization.

The region lifter (:mod:`code_virtualization_region`) and the interpreter/blob
code generator (:mod:`code_virtualization_region_codegen`) both depend on the
:class:`Region`/:class:`RegionScheme` value objects and on the canonical
item->handler-key mapping. Keeping them here lets the lifter and the code
generator import a common base without importing each other.
"""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_engine import VirtualizedOp

# Multiplying a byte by these broadcasts it into every lane of a dword/qword, so
# the per-item position byte (held in r13b) can un-mask a multi-byte immediate or
# displacement the encoder masked byte-wise. Shared by the code generator's
# dispatch/retarget and the handler bodies.
_QWORD_BROADCAST = 0x0101010101010101
_DWORD_BROADCAST = 0x01010101


class RegionScheme:
    """Per-instance handler layout, bytecode key, and register-slot layout.

    ``dup`` maps each handler key to the tuple of dense opcode indices that
    decode to it: an operation gets one or more interchangeable handler
    instances (each emitted with its own junk), so the opcode->operation map is
    not one-to-one and the same operation can appear as different opcodes in the
    stream. ``slot_perm`` is a per-instance bijection ``logical register index
    -> frame slot``: each register spills to a shuffled slot rather than its
    ModR/M-ordered one, so the context frame cannot be labelled positionally and
    slot indices in the bytecode reveal no register.
    """

    __slots__ = (
        "dup",
        "xor_key",
        "junk_seed",
        "slot_perm",
        "table_key",
        "field_perm",
        "body_seed",
        "checksum_offset",
        "flags_offset",
        "isa_seed",
    )

    def __init__(
        self,
        dup: dict[str, tuple[int, ...]],
        xor_key: int,
        junk_seed: int,
        slot_perm: tuple[int, ...],
        table_key: int,
        field_perm: int = 0,
        body_seed: int = 0,
        checksum_offset: int = 0x88,
        flags_offset: int = 0x80,
        isa_seed: int = 0,
    ) -> None:
        self.dup = dup
        self.xor_key = xor_key
        self.junk_seed = junk_seed
        self.slot_perm = slot_perm
        # 32-bit key the dispatch table offsets are XOR-encrypted with, so the
        # handler addresses are not a plaintext jump table for a devirtualizer.
        self.table_key = table_key
        # Seed for the per-build operand field-order permutation: the encoder and
        # the handlers both derive each item's field offsets from it, so a build
        # lays operands out in its own order and a devirtualizer's field-offset
        # model does not transfer across samples. 0 is the identity layout.
        self.field_perm = field_perm
        # Seeds the per-handler scratch-register bijection: each pure-VM-internal
        # handler instance derives its own permutation of the scratch pool from
        # this, so duplicate handlers share no register-allocation fingerprint.
        # 0 leaves the bodies in their canonical register spelling.
        self.body_seed = body_seed
        # Frame byte offset of the runtime self-checksum, relocated per build so the
        # checksum slot is not a fixed frame fingerprint. Lives in the free gap above
        # the flags slot and below the xmm save area; 0x88 is the canonical default.
        self.checksum_offset = checksum_offset
        # Frame byte offset of the captured RFLAGS slot, relocated per build so it is
        # not a fixed frame fingerprint. Qword-aligned in [0x80, 0x100), distinct
        # from the checksum slot; 0x80 is the canonical default.
        self.flags_offset = flags_offset
        # Seeds this build's semantic ISA personality: which of several equivalent
        # implementations each handler family uses (currently the flag-synthesis
        # spelling; see code_virtualization_region_isa). 0 is the canonical
        # personality, byte-identical to the pre-feature handlers.
        self.isa_seed = isa_seed


class Region:
    """A lowered single-exit function ready to encode to VM bytecode.

    ``instructions`` is a flat list of VM items; branch items carry the index
    of their target item. ``exit_vaddr`` is the native terminator the VM jumps
    back to. ``op_keys`` is the set of interpreter handlers the region needs.

    ``target_map`` maps a native instruction address to the index of its item, for
    the addresses a computed jump (``ijmp``) may resolve to at runtime. It is empty
    for the straight-line contract (no computed jumps) and populated only by the
    dispatch-region contract, so an ordinary region encodes byte-identically.
    """

    __slots__ = ("instructions", "exit_vaddr", "entry_vaddr", "op_keys", "body_ranges", "target_map")

    def __init__(
        self,
        instructions: list[tuple[Any, ...]],
        exit_vaddr: int,
        entry_vaddr: int,
        op_keys: set[str],
        body_ranges: list[tuple[int, int]],
        target_map: dict[int, int] | None = None,
    ) -> None:
        self.instructions = instructions
        self.exit_vaddr = exit_vaddr  # default exit, used by the unknown-opcode guard
        self.entry_vaddr = entry_vaddr
        self.op_keys = op_keys
        self.body_ranges = body_ranges  # (addr, size) of each virtualized body instruction
        self.target_map = target_map if target_map is not None else {}


def _op_key(item: tuple[Any, ...]) -> str | None:
    kind = item[0]
    if kind == "lea":
        return f"lea_{item[4]}"
    if kind == "learip":
        return f"learip_{item[3]}"
    if kind == "leaidx":
        return f"leaidx_{item[6]}"
    if kind == "leaidxnb":
        return f"leaidxnb_{item[5]}"
    if kind == "opmemidx":
        return f"opmemidx_{item[1]}_{item[7]}"
    if kind == "incdec":
        return f"incdec_{item[1]}_{item[3]}"
    if kind == "movx":
        return f"movx_{item[1]}_{item[2]}_{item[3]}"
    if kind == "movxidx":
        return f"movxidx_{item[1]}_{item[2]}_{item[3]}"
    if kind in ("load", "store", "fpload", "fpstore"):
        return f"{kind}_{item[4]}"
    if kind in ("fploadrip", "fpstorerip"):
        return f"{kind}_{item[3]}"
    if kind in ("fploadidx", "fpstoreidx"):
        return f"{kind}_{item[6]}"
    if kind in ("fploadidxnb", "fpstoreidxnb"):
        return f"{kind}_{item[5]}"
    if kind == "fparith":
        return f"fparith_{item[1]}_{item[4]}"
    if kind == "fparithmem":
        return f"fparithmem_{item[1]}_{item[5]}"
    if kind == "fparithmemrip":
        return f"fparithmemrip_{item[1]}_{item[4]}"
    if kind == "fparithmemidx":
        return f"fparithmemidx_{item[1]}_{item[7]}"
    if kind in ("cvti2f", "cvtf2i"):
        return f"{kind}_{item[1]}_{item[2]}"  # fp_width, gp_width
    if kind == "fpcmp":
        return f"fpcmp_{item[1]}"
    if kind == "fpmov":
        return f"fpmov_{item[1]}"
    if kind == "fppacked":
        return f"fppacked_{item[1]}"
    if kind == "fppackedmem":
        return f"fppackedmem_{item[1]}"
    if kind == "fppackedmemrip":
        return f"fppackedmemrip_{item[1]}"
    if kind == "fppackedmemidx":
        return f"fppackedmemidx_{item[1]}"
    if kind in ("fppload", "fppstore", "fpploadrip", "fppstorerip", "fpploadidx", "fppstoreidx"):
        return kind
    if kind in ("riprel_load", "riprel_store"):
        return f"{kind}_{item[3]}"
    if kind == "cmpmem":
        return f"cmpmem_{item[4]}"
    if kind == "cmpriprel":
        return f"cmpriprel_{item[3]}"
    if kind == "opmem":
        return f"opmem_{item[1]}_{item[5]}"
    if kind == "opriprel":
        return f"opriprel_{item[1]}_{item[4]}"
    if kind == "opmemdst":
        return f"opmemdst_{item[1]}_{item[5]}"
    if kind == "opmemdstrip":
        return f"opmemdstrip_{item[1]}_{item[4]}"
    if kind == "vpush":
        return "vpush"  # slot push primitive (one slot operand, no width)
    if kind == "vpop":
        return "vpop"  # slot pop primitive (one slot operand, no width)
    if kind == "vpushi":
        return f"vpushi_{item[2]}"  # immediate push, width-sized cell
    if kind == "vbinop":
        return f"vbinop_{item[1]}_{item[2]}"  # flag-dead stack fold: mnemonic + width
    if kind == "vbinopsynth":
        return f"vbinopsynth_{item[1]}_{item[2]}"  # flag-live stack fold: mnemonic + width
    if kind == "vload":
        return f"vload_{item[3]}"  # push [base+disp] onto the vstack: width
    if kind == "vstore":
        return f"vstore_{item[3]}"  # pop the vstack top to [base+disp]: width
    if kind == "vloadidx":
        return f"vloadidx_{item[5]}"  # push [base+index*scale+disp] onto the vstack: width
    if kind == "vloadrip":
        return f"vloadrip_{item[2]}"  # push [rip+disp] onto the vstack: width
    if kind == "vlea":
        return f"vlea_{item[3]}"  # push lea address of [base+disp] onto the vstack: width
    if kind == "vlearip":
        return f"vlearip_{item[2]}"  # push lea address of [rip+disp] onto the vstack: width
    if kind == "vleaidx":
        return f"vleaidx_{item[5]}"  # push lea address of [base+index*scale+disp]: width
    if kind == "vleaidxnb":
        return f"vleaidxnb_{item[4]}"  # push lea address of [index*scale+disp] (no base): width
    if kind == "vmovx":
        return f"vmovx_{item[1]}_{item[2]}_{item[3]}"  # push extended [base+disp]: ext, src_size, dst_width
    if kind == "vmovxidx":
        return f"vmovxidx_{item[1]}_{item[2]}_{item[3]}"  # push extended indexed load: ext, src_size, dst_width
    if kind == "vstorerip":
        return f"vstorerip_{item[2]}"  # pop the vstack top to [rip+disp]: width
    if kind == "vshift":
        return f"vshift_{item[1]}_{item[3]}"  # stack shift: mnemonic + width
    if kind == "vcmpsynth":
        return f"vcmpsynth_{item[1]}_{item[2]}"  # stack compare (flags only): op + width
    if kind in ("op", "opmba", "opsynth"):
        op: VirtualizedOp = item[1]
        # opsynth: a flag-live add/sub computed by MBA with hand-synthesized flags.
        return f"{kind}_{op.mnemonic}_{'i' if op.is_immediate else 'r'}_{op.width}"
    if kind == "cmp":
        return f"cmp_{'i' if item[3] else 'r'}_{item[4]}"
    if kind == "test":
        return f"test_{'i' if item[3] else 'r'}_{item[4]}"
    if kind == "shift":
        return f"{item[1]}_{item[4]}"
    if kind == "imul":
        return f"imul_{item[3]}"
    if kind == "imul3":
        return f"imul3_{item[4]}"
    if kind == "push":
        return f"push_{item[2]}"
    if kind == "pop":
        return f"pop_{item[2]}"
    if kind == "pushi":
        return "pushi"
    if kind == "rspadj":
        return f"rspadj_{item[1]}"
    if kind == "movfromrsp":
        return "movfromrsp"
    if kind == "movtorsp":
        return "movtorsp"
    if kind == "leave":
        return "leave"
    if kind == "call":
        return "call"  # bridge out to a native callee and back
    if kind == "icall":
        return "icall"  # register-indirect call (target from a frame slot)
    if kind == "callmem":
        return "callmem"  # memory-indirect call (target pointer at base+disp)
    if kind == "callmemrip":
        return "callmemrip"  # memory-indirect call (target pointer at rip+disp)
    if kind == "callmemidx":
        return "callmemidx"  # memory-indirect call (pointer at base+index*scale+disp)
    if kind == "jmp":
        return "jmp"
    if kind == "ijmp":
        return "ijmp"  # register-indirect jump: computed VM exit to a runtime target
    if kind == "fsave":
        return "fsave"  # native pushfq: save the virtual RFLAGS onto the vstack
    if kind == "frestore":
        return "frestore"  # native popfq: restore the virtual RFLAGS from the vstack
    if kind == "jcc":
        return f"jcc_{item[1]}"
    if kind == "nop":
        return "nop"
    if kind == "exit":
        return f"exit_{item[1]}"
    if kind == "enter_inner":
        return "enter_inner"  # transfer to the nested inner VM layer
    if kind == "inner_exit":
        return "inner_exit"  # return from a nested inner VM layer to its parent
    return None


def _required_key(item: tuple[Any, ...]) -> str:
    """The handler key for an item that must have one (all but exit)."""
    key = _op_key(item)
    if key is None:
        raise ValueError(f"item has no handler key: {item[0]}")
    return key
