"""
Code Virtualization - replace native register code with custom VM bytecode.

Selected straight-line runs of 64-bit general-purpose register instructions
are translated into bytecode for a small stack-context virtual machine. The
native run is overwritten with a trampoline into a generated interpreter
(injected into an extended executable segment); the interpreter spills the
registers to a private stack frame, executes the bytecode against that
context, reloads the registers, and jumps back to the instruction following
the run. The architectural effect is identical, but the original opcodes no
longer appear linearly in the code.

Correctness is enforced by hard gates (see
:mod:`r2morph.mutations.code_virtualization_engine` and
:mod:`r2morph.mutations.code_virtualization_inject`): only provably
reproducible runs on injectable ELF64 binaries are virtualized; every other
case leaves the function untouched. Zero virtualizations always beats a
corrupt one.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Any, cast

import r2morph.core.randomness as random
from r2morph.core.constants import MAX_FUNCTION_ANALYSIS_COUNT
from r2morph.mutations import code_virtualization_region_classification as classification
from r2morph.mutations.base import MutationPass
from r2morph.mutations.code_virtualization_apply import _DEFAULT_MAX_FUNCTION_SIZE, apply_code_virtualization
from r2morph.mutations.code_virtualization_dispatch_lifting import (
    RegionOptions,
    block_ops,
    complete_direct_branch_ops,
    gather_cfg_ops,
    gather_dispatch_ops,
    reachable_blocks,
    virtualize_dispatch_function,
)
from r2morph.mutations.code_virtualization_engine import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedImmediateOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
    VirtualizedFpScalarVexOp,
    VirtualizedMemOp,
    VirtualizedOp,
    build_vm_blob,
    build_vm_scheme,
    decode_instruction,
    inject_junk_ops,
)
from r2morph.mutations.code_virtualization_engine_models import VirtualizedAddress
from r2morph.mutations.code_virtualization_inject import inject_blob, predict_blob_vaddr
from r2morph.mutations.code_virtualization_region import (
    _is_syscall_instruction,
    _trim_after_unreferenced_terminal_syscall,
    _trim_trailing_padding,
    build_region_scheme,
    extract_region,
    region_supports_unwind_contract,
)
from r2morph.mutations.code_virtualization_region_codegen import (
    build_region_blob,
    call_unwind_ranges,
    call_unwind_ranges_with_sites,
    region_entry_vaddrs,
)
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    FpIndexedItem,
    FpIndexedNoBaseItem,
    _decode_fp_arith,
    _decode_fp_arith_idx,
    _decode_fp_arith_mem,
    _decode_fp_arith_riprel,
    _decode_fp_convert,
    _decode_fp_indexed,
    _decode_fp_mem,
    _decode_fp_packed_arith,
    _decode_fp_packed_immediate,
    _decode_fp_packed_indexed,
    _decode_fp_packed_mem,
    _decode_fp_packed_riprel,
    _decode_fp_riprel,
    _decode_fp_vex_packed_arith,
    _decode_fp_vex_scalar_arith,
)
from r2morph.mutations.code_virtualization_region_fp_extra_decoders import _decode_fp_vex_extra
from r2morph.mutations.code_virtualization_region_fp_packed_extra import _decode_fp_packed_arith_extra
from r2morph.mutations.code_virtualization_region_handlers import frame_size_for_seed
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _decode_lea,
    _decode_lea_indexed,
    _decode_memory_mov,
    _decode_memory_mov_indexed,
    _decode_movx,
    _decode_op_mem,
    _decode_op_mem_indexed,
    _decode_riprel_mov,
)
from r2morph.mutations.code_virtualization_region_nesting import build_nested_region_blob
from r2morph.mutations.instruction_substitution_helpers import flags_live_after
from r2morph.platform.elf_unwind import VmEhFrameSpec, build_vm_eh_frame, build_vm_eh_frame_with_lsda

logger = logging.getLogger(__name__)

_FP_INDEXED_TUPLE_SIZE = 7
_FP_INDEXED_NO_BASE_TUPLE_SIZE = 6
_FP_PACKED_INDEXED_TUPLE_SIZE = 6
_FP_PACKED_INDEXED_NO_BASE_TUPLE_SIZE = 5
PackedIndexedItem = tuple[str, int, int, int, int, int]
PackedIndexedNoBaseItem = tuple[str, int, int, int, int]
_FP_SINGLE_WIDTH_BITS = 32
_BYTE_WIDTH_BITS = 8
_WORD_WIDTH_BITS = 16
_DWORD_WIDTH_BITS = 32
_MIN_NESTING_DEPTH = 2
_REPEAT_PREFIXES = ("rep ", "repe ", "repne ", "repz ", "repnz ")
_INSTRUCTION_ENCODING_PREFIXES = (
    "rex ",
    "rex.w ",
    "rex.r ",
    "rex.x ",
    "rex.b ",
    "data16 ",
    "addr32 ",
)
_CONTROL_TRANSFER_PREFIXES = (
    *_REPEAT_PREFIXES,
    *_INSTRUCTION_ENCODING_PREFIXES,
    "notrack ",
    "bnd ",
)
_DIAGNOSTIC_PREFIXES = (*_REPEAT_PREFIXES, *_INSTRUCTION_ENCODING_PREFIXES)
_SYNC_PREFIXES = ("xacquire ", "xrelease ")


def _strip_opcode_prefixes(opcode: str, prefixes: tuple[str, ...]) -> str:
    stripped = opcode
    while True:
        next_opcode = stripped
        for prefix in prefixes:
            next_opcode = next_opcode.removeprefix(prefix)
        if next_opcode == stripped:
            return stripped
        stripped = next_opcode


def _strip_control_transfer_prefixes(opcode: str) -> str:
    return _strip_opcode_prefixes(opcode, _CONTROL_TRANSFER_PREFIXES)


@dataclass(frozen=True, slots=True)
class _UnwindPayload:
    """Unwind data paired with an injected VM blob."""

    frame_size: int | None
    call_ranges: tuple[tuple[int, int, int], ...]
    lsda_template: (
        tuple[
            int,
            int,
            int | None,
            int,
            bytes,
            int,
            int | None,
        ]
        | None
    ) = None
    lsda_call_sites: tuple[tuple[int, int, int, int], ...] = ()
    personality: int | None = None


def _remap_lsda_call_sites(
    frame: Any,
    site_ranges: tuple[tuple[int, int, int, int, int], ...],
    landing_pad_targets: dict[int, int] | None = None,
) -> (
    tuple[
        tuple[int, int, int | None, int, bytes, int, int | None],
        tuple[tuple[int, int, int, int], ...],
        int,
    ]
    | None
):
    """Map protected native call-sites to VM handler ranges and native pads."""
    template = getattr(frame, "lsda_template", None)
    personality = getattr(frame, "personality", None)
    if template is None or not isinstance(personality, int):
        return None
    mapped: set[tuple[int, int, int, int]] = set()
    call_sites = tuple(getattr(frame, "lsda_call_sites", ()))
    native_sites = (
        tuple((site.start_address, site.end_address, site.landing_pad, site.action_index) for site in call_sites)
        if call_sites
        else _legacy_lsda_call_sites(frame)
    )
    for native_start, native_end, landing_pad, action_index in native_sites:
        if (
            not isinstance(native_start, int)
            or not isinstance(native_end, int)
            or native_end <= native_start
            or not isinstance(landing_pad, int)
            or not isinstance(action_index, int)
            or action_index < 0
        ):
            return None
        for vm_start, vm_end, _cfa, source_start, source_end in site_ranges:
            if source_start < native_end and native_start < source_end:
                target = landing_pad
                if landing_pad_targets is not None:
                    # Isolated landing-pad regions may be emitted one at a time.
                    # Keep sibling LSDA targets at their native addresses until
                    # their own trampoline is installed; those addresses remain
                    # valid exception entries throughout the sequence.
                    target = landing_pad_targets.get(landing_pad, landing_pad)
                mapped.add((vm_start, vm_end, target, action_index))
    if not mapped:
        return None
    return (
        (
            template.landing_pad_encoding,
            template.type_encoding,
            template.type_table_offset,
            template.action_table_offset,
            template.action_and_type_bytes,
            _LSDA_REMAP_CALL_SITE_ENCODING,
            template.type_table_delta,
        ),
        tuple(sorted(mapped)),
        personality,
    )


def _legacy_lsda_call_sites(frame: Any) -> tuple[tuple[int, int, int, int], ...]:
    """Adapt synthetic frames created before the full LSDA row model existed."""
    sites: list[tuple[int, int, int, int]] = []
    for landing_pad in getattr(frame, "landing_pads", ()):
        if not isinstance(landing_pad.address, int):
            return ()
        metadata = landing_pad.metadata
        for site in (metadata, *metadata.get("call_sites", [])):
            if not isinstance(site, dict):
                return ()
            native_start = site.get("call_site_start")
            native_end = site.get("call_site_end")
            action_index = site.get("action_index")
            if (
                not isinstance(native_start, int)
                or not isinstance(native_end, int)
                or not isinstance(action_index, int)
            ):
                return ()
            sites.append((native_start, native_end, landing_pad.address, action_index))
    return tuple(sites)


_LANDING_PAD_TERMINATORS = frozenset(
    {"ret", "jmp", "ujmp", "rjmp", "ijmp", "mjmp", "irjmp", "swi", "trap", "invalid", "udf"}
)
_LANDING_PAD_CALLS = frozenset({"call", "rcall", "ucall", "icall"})


def _landing_pad_native_ranges(
    instructions: list[dict[str, Any]], frame: Any | None
) -> tuple[tuple[int, int], ...] | None:
    """Return the instruction ranges that must remain native for LSDA handlers."""
    landing_pads = tuple(getattr(frame, "landing_pads", ())) if frame is not None else ()
    if not landing_pads:
        return ()
    by_address = {int(instruction["addr"]): instruction for instruction in instructions}
    native_addresses: set[int] = set()
    for landing_pad in landing_pads:
        start = getattr(landing_pad, "address", None)
        if not isinstance(start, int):
            return None
        if start not in by_address:
            continue
        pending = [start]
        while pending:
            address = pending.pop()
            if address in native_addresses:
                continue
            instruction = by_address.get(address)
            if instruction is None:
                return None
            native_addresses.add(address)
            kind = str(instruction.get("type", "")).lower()
            if kind not in _LANDING_PAD_CALLS:
                for key in ("jump", "fail"):
                    target = instruction.get(key)
                    if isinstance(target, int) and target in by_address:
                        pending.append(target)
            if kind in _LANDING_PAD_TERMINATORS:
                continue
            next_address = address + int(instruction.get("size", 0))
            if next_address in by_address:
                pending.append(next_address)
    return tuple(
        sorted(
            (
                address,
                address + int(by_address[address].get("size", 0)),
            )
            for address in native_addresses
            if int(by_address[address].get("size", 0)) > 0
        )
    )


def _landing_pad_ops(
    instructions: list[dict[str, Any]], landing_pad_address: int, other_pad_addresses: frozenset[int]
) -> list[dict[str, Any]] | None:
    """Collect one landing-pad path without crossing into a sibling pad."""
    by_address = {int(instruction["addr"]): instruction for instruction in instructions}
    if landing_pad_address not in by_address:
        return None
    selected: set[int] = set()
    pending = [landing_pad_address]
    while pending:
        address = pending.pop()
        if address in selected or address not in by_address:
            continue
        if address != landing_pad_address and address in other_pad_addresses:
            continue
        instruction = by_address[address]
        selected.add(address)
        kind = str(instruction.get("type", "")).lower()
        if kind == "cjmp":
            for key in ("jump", "fail"):
                target = instruction.get(key)
                if isinstance(target, int):
                    pending.append(target)
        elif kind not in _LANDING_PAD_TERMINATORS:
            next_address = address + int(instruction.get("size", 0))
            if next_address in by_address:
                pending.append(next_address)
    return [by_address[address] for address in sorted(selected)]


def _extend_landing_pad_ops(
    binary: Any,
    instructions: list[dict[str, Any]],
    frame: Any | None,
    function_range: tuple[int, int] | None,
) -> list[dict[str, Any]] | None:
    """Add exception-only blocks omitted by radare2's function disassembly."""
    landing_pads = tuple(getattr(frame, "landing_pads", ())) if frame is not None else ()
    if not landing_pads:
        return instructions
    if function_range is None:
        return None
    by_address = {int(instruction["addr"]): instruction for instruction in instructions}
    for landing_pad in landing_pads:
        address = getattr(landing_pad, "address", None)
        if not isinstance(address, int) or not function_range[0] <= address < function_range[1]:
            return None
        try:
            disassembled = binary.r2.cmdj(f"pdj {_LANDING_PAD_DISASSEMBLY_LIMIT} @ {address}")
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            return None
        if not isinstance(disassembled, list):
            return None
        for instruction in disassembled:
            if not isinstance(instruction, dict):
                continue
            instruction_address = instruction.get("addr")
            instruction_size = instruction.get("size")
            if (
                isinstance(instruction_address, int)
                and isinstance(instruction_size, int)
                and instruction_size > 0
                and function_range[0] <= instruction_address < function_range[1]
            ):
                by_address[instruction_address] = instruction
    return [by_address[address] for address in sorted(by_address)]


def _region_has_protected_call_site(region: Any, frame: Any) -> bool:
    call_sites = tuple(getattr(frame, "lsda_call_sites", ()))
    native_ranges = (
        tuple((site.start_address, site.end_address) for site in call_sites)
        if call_sites
        else tuple((start, end) for start, end, _pad, _action in _legacy_lsda_call_sites(frame))
    )
    return any(
        native_start < call_end and native_end > call_start
        for native_start, native_end in native_ranges
        for call_start, call_end, _item_index in region.call_site_items
    )


def _build_unwind_payload(
    blob: bytes,
    scheme: Any,
    region: Any,
    frame: Any,
    landing_pad_targets: dict[int, int] | None = None,
) -> _UnwindPayload | None:
    frame_size = frame_size_for_seed(scheme.junk_seed)
    if getattr(frame, "lsda_template", None) is None:
        call_ranges = call_unwind_ranges(blob, scheme, region)
        return None if call_ranges is None else _UnwindPayload(frame_size, call_ranges)
    ranges_with_sites = call_unwind_ranges_with_sites(blob, scheme, region)
    if ranges_with_sites is None:
        return None
    call_ranges = tuple(item[:3] for item in ranges_with_sites)
    lsda_info = _remap_lsda_call_sites(frame, ranges_with_sites, landing_pad_targets)
    if lsda_info is None:
        if _region_has_protected_call_site(region, frame):
            return None
        return _UnwindPayload(frame_size, call_ranges)
    template, call_sites, personality = lsda_info
    return _UnwindPayload(frame_size, call_ranges, template, call_sites, personality)


# Minimum instructions in a run worth virtualizing.
_MIN_RUN_LENGTH = 2
# A relative trampoline jump needs 5 bytes in the run's byte span.
_TRAMPOLINE_SIZE = 5
_EH_FRAME_ALIGNMENT = 4
# Signed absolute offsets keep native landing pads below the injected blob valid.
_LSDA_REMAP_CALL_SITE_ENCODING = 0x0B
_LANDING_PAD_DISASSEMBLY_LIMIT = 256
# Upper bound on instructions read when gathering a dispatch-shaped function
# linearly (its analysis stops at the computed jump, so there is no function size).
_MAX_DISPATCH_INSNS = 256
_MAX_UNSUPPORTED_RECORDS = 256
_MAX_DIAGNOSTIC_OPCODE_CHARS = 96
_COMPUTED_JUMP_TYPES = frozenset({"ujmp", "rjmp", "ijmp", "mjmp", "irjmp"})


_MEM_ARITH_MNEMONICS = ("add", "sub", "xor", "and", "or")
_MOVX_MEMORY_SUFFIXES = {
    ("z", _BYTE_WIDTH_BITS): "b",
    ("z", _WORD_WIDTH_BITS): "w",
    ("s", _BYTE_WIDTH_BITS): "b",
    ("s", _WORD_WIDTH_BITS): "w",
    ("s", _DWORD_WIDTH_BITS): "d",
}

VirtualizedRunItem = (
    VirtualizedOp
    | VirtualizedMemOp
    | VirtualizedFpMemOp
    | VirtualizedFpArithOp
    | VirtualizedFpScalarVexOp
    | VirtualizedFpConvertOp
    | VirtualizedFpArithMemOp
    | VirtualizedFpPackedOp
    | VirtualizedFpPackedImmediateOp
    | VirtualizedFpPackedMemOp
)


def _movx_memory_kind(extension: str, source_size: int, indexed: bool) -> str | None:
    suffix = _MOVX_MEMORY_SUFFIXES.get((extension, source_size))
    if suffix is None:
        return None
    return f"mov{extension}x{suffix}{'idx' if indexed else ''}"


def _decode_fp_memory_item(text: str, insn_addr: int, insn_size: int) -> VirtualizedFpMemOp | None:
    decoded = _decode_fp_mem(text)
    if decoded is not None:
        kind, xmm_index, base_slot, disp, width = decoded
        return VirtualizedFpMemOp(kind, xmm_index, VirtualizedAddress(base_slot, disp), width)
    rip_relative = _decode_fp_riprel(text, insn_addr, insn_size)
    if rip_relative is not None:
        kind, xmm_index, target, width = rip_relative
        return VirtualizedFpMemOp(kind, xmm_index, VirtualizedAddress(-1, target), width)
    indexed = _decode_fp_indexed(text)
    if indexed is not None and len(indexed) == _FP_INDEXED_TUPLE_SIZE:
        kind, xmm_index, base_slot, index_slot, shift, disp, width = cast(FpIndexedItem, indexed)
        return VirtualizedFpMemOp(
            kind,
            xmm_index,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    if indexed is not None and len(indexed) == _FP_INDEXED_NO_BASE_TUPLE_SIZE:
        kind, xmm_index, index_slot, shift, disp, width = cast(FpIndexedNoBaseItem, indexed)
        return VirtualizedFpMemOp(
            kind,
            xmm_index,
            VirtualizedAddress(-1, disp, index_slot, shift),
            width,
        )
    return None


def _decode_fp_arithmetic_item(text: str, insn_addr: int, insn_size: int) -> VirtualizedRunItem | None:
    decoded = _decode_fp_arith(text)
    if decoded is not None:
        _kind, operation, destination, source, width = decoded
        return VirtualizedFpArithOp(operation, destination, source, width)
    converted = _decode_fp_convert(text)
    if converted is not None:
        direction, fp_width, gp_width, first, second = converted
        xmm_index, gp_slot = (first, second) if direction == "cvti2f" else (second, first)
        return VirtualizedFpConvertOp(direction, fp_width, gp_width, xmm_index, gp_slot)
    memory = _decode_fp_arith_mem(text)
    if memory is not None:
        _kind, operation, xmm_index, base_slot, disp, width = memory
        return VirtualizedFpArithMemOp(operation, xmm_index, VirtualizedAddress(base_slot, disp, -1), width)
    rip_relative = _decode_fp_arith_riprel(text, insn_addr, insn_size)
    if rip_relative is not None:
        _kind, operation, xmm_index, target, width = rip_relative
        return VirtualizedFpArithMemOp(operation, xmm_index, VirtualizedAddress(-1, target, -1), width)
    indexed = _decode_fp_arith_idx(text)
    if indexed is not None:
        _kind, operation, xmm_index, base_slot, index_slot, shift, disp, width = indexed
        return VirtualizedFpArithMemOp(
            operation,
            xmm_index,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    return None


def _decode_fp_scalar_vex_item(text: str) -> VirtualizedFpScalarVexOp | None:
    decoded = _decode_fp_vex_scalar_arith(text)
    if decoded is None:
        return None
    _kind, operation, destination, first_source, second_source, width = decoded
    suffix = "ss" if width == _FP_SINGLE_WIDTH_BITS else "sd"
    return VirtualizedFpScalarVexOp(f"v{operation}{suffix}", destination, first_source, second_source)


def _decode_fp_vex_extra_item(text: str) -> VirtualizedFpPackedOp | None:
    extra = _decode_fp_vex_extra(text)
    if extra is None or extra[0] != "fppackedvex":
        return None
    _kind, mnemonic, destination, first_source, second_source = extra
    return VirtualizedFpPackedOp(
        f"v{mnemonic}",
        destination,
        second_source,
        vex=True,
        src1_index=first_source,
    )


def _decode_fp_packed_item(text: str, insn_addr: int, insn_size: int) -> VirtualizedRunItem | None:
    extra = _decode_fp_vex_extra_item(text)
    if extra is not None:
        return extra
    vex = _decode_fp_vex_packed_arith(text)
    if vex is not None:
        _kind, mnemonic, destination, first_source, second_source = vex
        return VirtualizedFpPackedOp(
            f"v{mnemonic}",
            destination,
            second_source,
            vex=True,
            src1_index=first_source,
        )
    immediate = _decode_fp_packed_immediate(text)
    if immediate is not None and immediate[1] != "pshufd":
        _kind, mnemonic, destination, immediate_value = immediate
        return VirtualizedFpPackedImmediateOp(mnemonic, destination, immediate_value)
    return _decode_fp_packed_non_immediate_item(text, insn_addr, insn_size)


def _decode_fp_packed_non_immediate_item(text: str, insn_addr: int, insn_size: int) -> VirtualizedRunItem | None:
    decoded = _decode_fp_packed_arith(text) or _decode_fp_packed_arith_extra(text)
    if decoded is not None:
        _kind, mnemonic, destination, source = decoded
        return VirtualizedFpPackedOp(mnemonic, destination, source)
    memory = _decode_fp_packed_mem(text)
    if memory is not None:
        kind, xmm_index, base_slot, disp = memory
        return VirtualizedFpPackedMemOp(kind, xmm_index, VirtualizedAddress(base_slot, disp))
    rip_relative = _decode_fp_packed_riprel(text, insn_addr, insn_size)
    if rip_relative is not None:
        kind, xmm_index, target = rip_relative
        return VirtualizedFpPackedMemOp(kind, xmm_index, VirtualizedAddress(-1, target))
    return _decode_fp_packed_indexed_item(text)


def _decode_fp_packed_indexed_item(text: str) -> VirtualizedFpPackedMemOp | None:
    indexed = _decode_fp_packed_indexed(text)
    if indexed is None:
        return None
    if len(indexed) == _FP_PACKED_INDEXED_TUPLE_SIZE:
        kind, xmm_index, base_slot, index_slot, shift, disp = cast(PackedIndexedItem, indexed)
        return VirtualizedFpPackedMemOp(kind, xmm_index, VirtualizedAddress(base_slot, disp, index_slot, shift))
    if len(indexed) == _FP_PACKED_INDEXED_NO_BASE_TUPLE_SIZE:
        kind, xmm_index, index_slot, shift, disp = cast(PackedIndexedNoBaseItem, indexed)
        return VirtualizedFpPackedMemOp(kind, xmm_index, VirtualizedAddress(-1, disp, index_slot, shift))
    return None


def _decode_indexed_gp_memory_item(text: str) -> VirtualizedMemOp | None:
    indexed = _decode_memory_mov_indexed(text)
    if indexed is None:
        return None
    kind = indexed[0]
    if kind.endswith("nb"):
        _, register_slot, index_slot, shift, disp, width = indexed
        return VirtualizedMemOp(kind, register_slot, VirtualizedAddress(-1, disp, index_slot, shift), width)
    _, register_slot, base_slot, index_slot, shift, disp, width = indexed
    return VirtualizedMemOp(kind, register_slot, VirtualizedAddress(base_slot, disp, index_slot, shift), width)


def _decode_gp_movx_item(text: str) -> VirtualizedMemOp | None:
    extended = _decode_movx(text)
    if extended is None:
        return None
    if extended[0] == "movx":
        _, extension, source_size, width, register_slot, base_slot, disp = extended
        kind = _movx_memory_kind(extension, source_size, indexed=False)
        if kind is None:
            return None
        return VirtualizedMemOp(kind, register_slot, VirtualizedAddress(base_slot, disp), width)
    if extended[0] == "movxidx":
        _, extension, source_size, width, register_slot, base_slot, index_slot, shift, disp = extended
        kind = _movx_memory_kind(extension, source_size, indexed=True)
        if kind is None:
            return None
        return VirtualizedMemOp(
            kind,
            register_slot,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    return None


def _decode_gp_memory_item(text: str, insn_addr: int, insn_size: int) -> VirtualizedMemOp | None:
    indexed = _decode_indexed_gp_memory_item(text)
    if indexed is not None and (indexed.width in (32, 64) or indexed.kind.startswith(("load", "store"))):
        return indexed
    decoded = _decode_memory_mov(text)
    if decoded is not None and (decoded[-1] in (32, 64) or decoded[0] in ("load", "store")):
        kind, register_slot, base_slot, disp, width = decoded
        return VirtualizedMemOp(kind, register_slot, VirtualizedAddress(base_slot, disp), width)
    movx = _decode_gp_movx_item(text)
    if movx is not None:
        return movx
    rip_relative = _decode_riprel_mov(text, insn_addr, insn_size)
    if rip_relative is not None:
        kind, register_slot, target, width = rip_relative
        return VirtualizedMemOp(
            "loadrip" if kind == "riprel_load" else "storerip",
            register_slot,
            VirtualizedAddress(-1, target),
            width,
        )
    return None


def _decode_memory_arithmetic_item(text: str, mnemonic: str, insn_addr: int, insn_size: int) -> VirtualizedMemOp | None:
    if mnemonic not in _MEM_ARITH_MNEMONICS:
        return None
    decoded = _decode_op_mem(text, mnemonic, insn_addr, insn_size)
    if decoded is not None and decoded[0] == "opmem" and decoded[-1] in (32, 64):
        _, _mnemonic, register_slot, base_slot, disp, width = decoded
        return VirtualizedMemOp(f"mem{mnemonic}", register_slot, VirtualizedAddress(base_slot, disp), width)
    if decoded is not None and decoded[0] == "opriprel" and decoded[-1] in (32, 64):
        _, _mnemonic, register_slot, target, width = decoded
        return VirtualizedMemOp(f"mem{mnemonic}rip", register_slot, VirtualizedAddress(-1, target), width)
    indexed = _decode_op_mem_indexed(text, mnemonic)
    if indexed is not None and indexed[0] == "opmemidx" and indexed[-1] in (32, 64):
        _, _mnemonic, register_slot, base_slot, index_slot, shift, disp, width = indexed
        return VirtualizedMemOp(
            f"mem{mnemonic}idx",
            register_slot,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    return None


def _decode_lea_item(text: str, mnemonic: str, insn_addr: int, insn_size: int) -> VirtualizedMemOp | None:
    if mnemonic != "lea":
        return None
    decoded = _decode_lea(text, insn_addr, insn_size)
    if decoded is not None and decoded[0] == "lea":
        _, register_slot, base_slot, disp, width = decoded
        return VirtualizedMemOp("lea", register_slot, VirtualizedAddress(base_slot, disp), width)
    if decoded is not None and decoded[0] == "learip":
        _, register_slot, target, width = decoded
        return VirtualizedMemOp("learip", register_slot, VirtualizedAddress(-1, target), width)
    indexed = _decode_lea_indexed(text)
    if indexed is not None and indexed[0] == "leaidx":
        _, register_slot, base_slot, index_slot, shift, disp, width = indexed
        return VirtualizedMemOp(
            "leaidx",
            register_slot,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    return None


def _decode_run_item(text: str, insn_addr: int = 0, insn_size: int = 0) -> VirtualizedRunItem | None:
    """Decode one instruction into a VM item: a register/immediate op, a memory
    load/store ``mov``, a scalar ``movsd``/``movss`` xmm<->[base+disp], an ``<op>
    reg, [base+disp]``, a ``mov reg, [rip+disp]``, or ``None`` if the VM cannot
    reproduce it (ends the run)."""
    op = decode_instruction(text)
    if op is not None:
        return op
    mnemonic = text.split(None, 1)[0].lower() if text.strip() else ""
    decoded_items = (
        _decode_fp_memory_item(text, insn_addr, insn_size),
        _decode_fp_scalar_vex_item(text),
        _decode_fp_arithmetic_item(text, insn_addr, insn_size),
        _decode_fp_packed_item(text, insn_addr, insn_size),
        _decode_gp_memory_item(text, insn_addr, insn_size),
        _decode_memory_arithmetic_item(text, mnemonic, insn_addr, insn_size),
        _decode_lea_item(text, mnemonic, insn_addr, insn_size),
    )
    return next((item for item in decoded_items if item is not None), None)


class _Run:
    """A virtualizable straight-line run inside one basic block."""

    __slots__ = ("continuation", "ops", "start")

    def __init__(
        self,
        start: int,
        continuation: int,
        ops: list[VirtualizedRunItem],
    ) -> None:
        self.start = start
        self.continuation = continuation
        self.ops = ops


@dataclass(frozen=True)
class _RunBuild:
    blob_vaddr: int
    blob: bytes
    original_bytes: bytes
    span: int


class CodeVirtualizationPass(MutationPass):
    """
    Mutation pass that virtualizes register runs into custom VM bytecode.

    Config options:
        - probability: Probability of virtualizing each function (default: 0.3)
        - max_functions: Maximum functions to virtualize (default: 5)
        - vm_nesting_depth: VM layers per function; 2 wraps the region in a
          second, independently-keyed inner VM (default: 2, nested when a
          peelable register-op run exists, single-layer otherwise)
        - reject_partial_virtualization: Reject a function when only a
          straight-line region can be proven (default: True)
        - max_function_size: Maximum native function size sent to static
          virtualization preflight (default: 65536 bytes)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="CodeVirtualization", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 5)
        self.vm_nesting_depth = self.config.get("vm_nesting_depth", 2)
        self.reject_partial_virtualization = self.config.get("reject_partial_virtualization", True)
        self.max_function_size = self.config.get("max_function_size", _DEFAULT_MAX_FUNCTION_SIZE)
        if not isinstance(self.max_function_size, int) or self.max_function_size < 1:
            raise ValueError("max_function_size must be a positive integer")
        self.max_function_analysis_count = self.config.get("max_function_analysis_count", MAX_FUNCTION_ANALYSIS_COUNT)
        if not isinstance(self.max_function_analysis_count, int) or self.max_function_analysis_count < 1:
            raise ValueError("max_function_analysis_count must be a positive integer")
        # Dispatch-shaped functions are inferred automatically; an explicit False
        # remains available for debugging and regression reproduction.
        self.virtualize_dispatch = self.config.get("virtualize_dispatch", True)
        self.set_support(
            formats=("ELF",),
            architectures=("x86_64",),
            validators=("structural",),
            stability="experimental",
            notes=(
                "translates 64-bit register runs to VM bytecode",
                "injects a generated interpreter into an extended segment",
                "leaves functions untouched when correctness cannot be proven",
            ),
        )

    def _find_run(self, binary: Any, block: dict[str, Any]) -> _Run | None:
        """Find the first virtualizable run inside a basic block.

        ``pdbj`` disassembles exactly the basic block, so a run never spans a
        block boundary - its interior can hold no jump target, and the
        trampoline cannot orphan an instruction reached by another edge.
        """
        try:
            insns = binary.r2.cmdj(f"pdbj @ {block['addr']}")
        except Exception:
            return None
        if not insns:
            return None

        disasms = [insn.get("opcode", "") for insn in insns]
        decoded = [_decode_run_item(insn.get("opcode", ""), insn.get("addr", 0), insn.get("size", 0)) for insn in insns]

        index = 0
        count = len(insns)
        while index < count:
            if decoded[index] is None:
                index += 1
                continue
            end = index
            while end < count and decoded[end] is not None:
                end += 1
            # A run must be followed by another instruction in the block to
            # supply the continuation address; the block's terminator (which
            # decode_instruction never accepts) provides it.
            if end < count and (end - index) >= _MIN_RUN_LENGTH and not flags_live_after(disasms, end - 1):
                start = insns[index]["addr"]
                continuation = insns[end]["addr"]
                if continuation - start >= _TRAMPOLINE_SIZE:
                    return _Run(start, continuation, [op for op in decoded[index:end] if op is not None])
            index = end
        return None

    @staticmethod
    def _build_run(binary: Any, run: _Run) -> _RunBuild | None:
        blob_vaddr = predict_blob_vaddr(binary)
        if blob_vaddr is None:
            return None
        rng = random.Random(random.getrandbits(64))
        ops = inject_junk_ops(run.ops, rng)
        blob = build_vm_blob(ops, blob_vaddr, run.continuation, build_vm_scheme(rng))
        if blob is None:
            return None
        span = run.continuation - run.start
        original_bytes = binary.read_bytes(run.start, span)
        if not original_bytes or len(original_bytes) != span:
            return None
        return _RunBuild(blob_vaddr, blob, bytes(original_bytes), span)

    def _install_run(self, binary: Any, run: _Run, build: _RunBuild) -> dict[str, Any] | None:
        checkpoint = self._create_mutation_checkpoint("virtualize")
        injected_vaddr = inject_blob(binary, build.blob)
        if injected_vaddr is None:
            return None
        if injected_vaddr != build.blob_vaddr:
            self._rollback_uncommitted(binary, checkpoint, reason="VM blob landed at an unexpected vaddr; aborting")
            return None
        relative = injected_vaddr - (run.start + _TRAMPOLINE_SIZE)
        trampoline = b"\xe9" + struct.pack("<i", relative) + b"\x90" * (build.span - _TRAMPOLINE_SIZE)
        if not binary.write_bytes(run.start, trampoline):
            self._rollback_uncommitted(binary, checkpoint, reason="failed to write VM trampoline; aborting")
            return None
        record = self._record_mutation(
            function_address=run.start,
            start_address=run.start,
            end_address=run.continuation - 1,
            original_bytes=build.original_bytes,
            mutated_bytes=binary.read_bytes(run.start, build.span),
            original_disasm=f"; {len(run.ops)} instructions",
            mutated_disasm=f"; trampoline -> VM ({len(build.blob)} bytes)",
            mutation_kind="code_virtualization",
            metadata={
                "instructions_count": len(run.ops),
                "affected_instruction_mnemonics": sorted(
                    {mnemonic for op in run.ops if isinstance(mnemonic := getattr(op, "mnemonic", None), str)}
                ),
                "bytecode_size": len(build.blob),
            },
        )
        if self._validate_mutation_or_rollback(binary, record, checkpoint):
            return None
        return {
            "instructions": len(run.ops),
            "bytecode": len(build.blob),
            "body_ranges": ((run.start, build.span),),
        }

    def _virtualize_run(self, binary: Any, run: _Run) -> dict[str, Any] | None:
        """Inject the VM for ``run`` and install the trampoline."""
        build = self._build_run(binary, run)
        return None if build is None else self._install_run(binary, run, build)

    def _virtualize_function(
        self, binary: Any, func: dict[str, Any], unwind_frame: Any | None = None
    ) -> dict[str, Any] | None:
        """Virtualize a whole single-exit function via the control-flow VM."""
        try:
            disasm = binary.r2.cmdj(f"pdfj @ {func['addr']}")
        except Exception:
            return None
        if not disasm or "ops" not in disasm:
            return None
        rng = random.Random(random.getrandbits(64))
        function_start = func.get("addr")
        function_size = func.get("size")
        function_min = func.get("minaddr", function_start)
        function_max = func.get("maxaddr")
        function_range = (
            (int(function_min), int(function_max))
            if isinstance(function_min, int) and isinstance(function_max, int) and function_max >= function_min
            else (
                (int(function_start), int(function_start) + int(function_size))
                if isinstance(function_start, int) and isinstance(function_size, int) and function_size > 0
                else None
            )
        )
        if unwind_frame is not None:
            frame_start = getattr(unwind_frame, "function_start", None)
            frame_end = getattr(unwind_frame, "function_end", None)
            if isinstance(frame_start, int) and isinstance(frame_end, int) and frame_end > frame_start:
                if function_range is None:
                    function_range = (frame_start, frame_end)
                else:
                    function_range = (
                        min(function_range[0], frame_start),
                        max(function_range[1], frame_end),
                    )
        complete_ops = complete_direct_branch_ops(binary, disasm["ops"], function_range)
        extended_ops = _extend_landing_pad_ops(binary, complete_ops, unwind_frame, function_range)
        if extended_ops is None:
            return None
        complete_ops = extended_ops
        try:
            known_function_ranges = tuple(
                (int(candidate["addr"]), int(candidate["addr"]) + int(candidate["size"]))
                for candidate in binary.get_functions()
                if isinstance(candidate.get("addr"), int)
                and isinstance(candidate.get("size"), int)
                and candidate["size"] > 0
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            known_function_ranges = None
        landing_pad_addresses = tuple(
            landing_pad.address
            for landing_pad in getattr(unwind_frame, "landing_pads", ())
            if isinstance(landing_pad.address, int)
        )
        landing_pad_stack_sources = tuple(
            (landing_pad.address, landing_pad.metadata["call_site_start"])
            for landing_pad in getattr(unwind_frame, "landing_pads", ())
            if isinstance(landing_pad.address, int)
            and isinstance(landing_pad.metadata, dict)
            and isinstance(landing_pad.metadata.get("call_site_start"), int)
        )
        native_ranges = () if landing_pad_addresses else _landing_pad_native_ranges(complete_ops, unwind_frame)
        if native_ranges is None:
            return None
        region = extract_region(
            complete_ops,
            rng,
            function_range=function_range,
            known_function_ranges=known_function_ranges,
            native_ranges=native_ranges,
            entry_addresses=landing_pad_addresses,
            entry_stack_sources=landing_pad_stack_sources,
        )
        if region is not None:
            result = self._emit_region(binary, func, region, RegionOptions(rng, True, unwind_frame))
            if result is not None:
                return result
        if landing_pad_addresses and not self._virtualize_landing_pads(
            binary,
            func,
            complete_ops,
            landing_pad_addresses,
            RegionOptions(rng, False, unwind_frame, False),
        ):
            logger.debug("Landing-pad VM construction was incomplete for 0x%x", func["addr"])
        return None

    def _virtualize_landing_pads(
        self,
        binary: Any,
        func: dict[str, Any],
        instructions: list[dict[str, Any]],
        landing_pad_addresses: tuple[int, ...],
        options: RegionOptions,
    ) -> bool:
        """Virtualize each exception entry while retaining its native LSDA address."""
        pad_addresses = frozenset(landing_pad_addresses)
        for address in landing_pad_addresses:
            pad_ops = _landing_pad_ops(instructions, address, pad_addresses)
            if not pad_ops:
                return False
            region = extract_region(
                pad_ops,
                options.rng,
                function_range=None,
                known_function_ranges=None,
                native_ranges=(),
                entry_addresses=(address,),
            )
            if region is None or region.entry_vaddr != address:
                return False
            if self._emit_region(binary, func, region, options) is None:
                return False
        return True

    def _gather_dispatch_ops(self, binary: Any, func: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Linear instruction list of a dispatch-shaped function.

        A computed-goto loop's function analysis stops at the register-indirect
        jump (r2 cannot follow it), so ``pdfj`` returns a truncated body. Read the
        function linearly from its entry to the first terminator instead.
        """
        return gather_dispatch_ops(binary, func)

    def _reachable_blocks(self, by_addr: dict[int, dict[str, Any]], entry: int) -> set[int]:
        """Block addresses reachable from ``entry`` over r2's resolved edges.

        Follows each block's static ``jump``/``fail`` successors and, for a resolved
        switch block, its ``switch_op`` case targets and default - so every case block
        r2 discovered is gathered without reading or guessing the jump table.
        """
        return reachable_blocks(by_addr, entry)

    def _block_ops(
        self, binary: Any, entry: int, by_addr: dict[int, dict[str, Any]], reachable: set[int]
    ) -> list[dict[str, Any]]:
        """Materialize the instructions of the reachable blocks, address-sorted.

        Prefers ``pdfj`` (one call covering a fully-resolved function) and fills any
        reachable block it did not cover with a per-block ``pdbj``.
        """
        return block_ops(binary, entry, by_addr, reachable)

    def _gather_cfg_ops(self, binary: Any, func: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Gather a function's full CFG closure from r2's block analysis.

        Returns an entry-first, address-sorted op list covering every block reachable
        from the entry over static and resolved-switch edges, or ``None`` when the
        function is not a resolved switch (the caller then falls back to the linear
        dispatch gather). Gating on a resolved ``switch_op`` keeps the whole-function
        ``pdfj`` path responsible for ordinary multi-block functions and never guesses
        an extent for an unresolved computed jump.
        """
        return gather_cfg_ops(binary, func)

    def _virtualize_dispatch_function(
        self, binary: Any, func: dict[str, Any], unwind_frame: Any | None = None
    ) -> dict[str, Any] | None:
        """Virtualize a dispatch-shaped function (opt-in), lowering its computed
        jump to an ijmp that re-enters the VM at the virtualized target."""
        return virtualize_dispatch_function(self, binary, func, unwind_frame)

    def _has_computed_jump(self, binary: Any, func: dict[str, Any]) -> bool:
        """Detect dispatch-shaped functions before the ordinary region path."""
        return self._find_computed_jump(binary, func) is not None

    def _find_computed_jump(self, binary: Any, func: dict[str, Any]) -> dict[str, Any] | None:
        """Return the first computed jump that blocks the default VM path."""
        try:
            blocks = binary.r2.cmdj(f"afbj @ {func['addr']}") or []
        except (ValueError, OSError, BrokenPipeError, RuntimeError):
            return None
        block_ranges = tuple(
            (int(block["addr"]), int(block["size"]))
            for block in blocks
            if isinstance(block, dict)
            and isinstance(block.get("addr"), int)
            and isinstance(block.get("size"), int)
            and block["size"] > 0
        )
        if block_ranges:
            try:
                ops = [
                    op
                    for address, size in block_ranges
                    for op in (binary.r2.cmdj(f"pdj {size} @ {address}") or [])
                    if isinstance(op, dict)
                ]
            except (ValueError, OSError, BrokenPipeError, RuntimeError):
                return None
        else:
            try:
                ops = binary.r2.cmdj(f"pdj {_MAX_DISPATCH_INSNS} @ {func['addr']}") or []
            except (ValueError, OSError, BrokenPipeError, RuntimeError):
                return None
        start = func.get("addr")
        size = func.get("size")
        end = start + size if isinstance(start, int) and isinstance(size, int) and size > 0 else None
        return next(
            (
                op
                for op in ops
                if op.get("type") in _COMPUTED_JUMP_TYPES and (end is None or start <= op.get("addr", -1) < end)
            ),
            None,
        )

    def _find_first_unvirtualizable_instruction(self, binary: Any, func: dict[str, Any]) -> dict[str, Any] | None:
        """Find the first instruction rejected by the whole-function classifier."""
        try:
            disasm = binary.r2.cmdj(f"pdfj @ {func['addr']}")
        except (ValueError, OSError, BrokenPipeError, RuntimeError):
            return None
        if not isinstance(disasm, dict):
            return None
        instructions = _trim_trailing_padding(
            [instruction for instruction in disasm.get("ops", []) if isinstance(instruction, dict)]
        )
        instructions = _trim_after_unreferenced_terminal_syscall(instructions)
        for instruction in instructions:
            kind = instruction.get("type")
            opcode_parts = str(instruction.get("opcode", "")).lower().split(maxsplit=1)
            opcode_mnemonic = opcode_parts[0] if opcode_parts else ""
            if kind == "ret" and (
                not opcode_mnemonic
                or (
                    opcode_mnemonic in {"ret", "retq", "retn", "retl", "retw"}
                    and (
                        len(opcode_parts) == 1
                        or classification._decode_ret_cleanup(str(instruction.get("opcode", ""))) is not None
                    )
                )
            ):
                continue
            if _is_syscall_instruction(instruction):
                continue
            if classification._classify(instruction, allow_computed_jump=self.virtualize_dispatch) is None:
                return instruction
        return None

    @staticmethod
    def _unsupported_instruction_diagnostic(instruction: dict[str, Any] | None) -> tuple[str, str]:
        """Map a rejected instruction to a stable capability label and reason."""
        if instruction is None:
            return "ssa_liveness", "CFG, SSA, and liveness coverage were not proven"
        kind = str(instruction.get("type", ""))
        opcode = str(
            instruction.get("opcode") or instruction.get("disasm") or instruction.get("mnemonic") or ""
        ).lower()
        opcode_terms = opcode.replace(",", " ").replace("[", " ").replace("]", " ").split()
        opcode_without_repeat = _strip_opcode_prefixes(opcode, _REPEAT_PREFIXES)
        opcode_without_encoding_prefix = _strip_opcode_prefixes(opcode, _DIAGNOSTIC_PREFIXES)
        opcode_without_sync_prefix = _strip_opcode_prefixes(opcode, (*_DIAGNOSTIC_PREFIXES, *_SYNC_PREFIXES))
        mnemonic_parts = opcode_without_encoding_prefix.split(maxsplit=1)
        mnemonic = mnemonic_parts[0] if mnemonic_parts else ""
        control_opcode = _strip_control_transfer_prefixes(opcode_without_repeat)
        control_mnemonic_parts = control_opcode.split(maxsplit=1)
        control_mnemonic = control_mnemonic_parts[0] if control_mnemonic_parts else ""
        if (
            kind in _COMPUTED_JUMP_TYPES
            or control_mnemonic.startswith(("loop", "jcxz", "jecxz", "jrcxz"))
            or control_opcode.startswith(("jmpf", "ljmp"))
            or (
                control_mnemonic in {"jmp", "jmpq"}
                and len(control_mnemonic_parts) > 1
                and ("[" in opcode or not control_mnemonic_parts[1].startswith(("0x", "$")))
            )
        ):
            capability, reason = "computed_control_flow", "computed control flow is not enabled for this pass"
        elif (
            "fs:" in opcode
            or "gs:" in opcode
            or any(term in {"fs", "gs"} for term in opcode_terms)
            or opcode_without_encoding_prefix.startswith(("lfs", "lgs"))
            or opcode_without_encoding_prefix.startswith(("rdfsbase", "rdgsbase", "swapgs", "wrfsbase", "wrgsbase"))
        ):
            capability, reason = "thread_local_storage", "thread-local storage addressing semantics were not proven"
        elif (
            (
                opcode_without_sync_prefix.startswith(
                    (
                        "cmpxchg",
                        "xadd",
                    )
                )
                and "[" in opcode
            )
            or opcode_without_sync_prefix.startswith(
                (
                    "mfence",
                    "lfence",
                    "monitor",
                    "monitorx",
                    "mwait",
                    "mwaitx",
                    "pause",
                    "sfence",
                    "tpause",
                    "umonitor",
                    "umwait",
                    "xabort",
                    "xbegin",
                    "xend",
                    "xresldtrk",
                    "xsusldtrk",
                    "xtest",
                    "lock ",
                )
            )
            or (opcode_without_sync_prefix.startswith("xchg") and "[" in opcode)
        ):
            capability, reason = "thread_synchronization", "atomic synchronization semantics were not proven"
        elif kind in ("swi", "syscall") or opcode_without_encoding_prefix.startswith(
            (
                "clui",
                "int ",
                "int1",
                "int3",
                "into",
                "icebp",
                "iret",
                "senduipi",
                "stui",
                "syscall",
                "sysenter",
                "sysret",
                "sysexit",
                "testui",
                "ud0",
                "ud1",
                "ud2",
                "uiret",
            )
        ):
            capability, reason = "signals_and_system_calls", "system-call and interrupt semantics were not proven"
        elif "call" in kind or control_opcode.startswith(("call", "callf", "lcall")):
            capability, reason = "calls", "call semantics were not proven for whole-function virtualization"
        elif (
            (kind == "ret" and len(mnemonic_parts) > 1)
            or (mnemonic == "ret" and len(mnemonic_parts) > 1)
            or (mnemonic in {"retq", "retn", "retl", "retw"} and len(mnemonic_parts) > 1)
            or mnemonic in {"retf", "retfq", "lret", "lretq"}
            or mnemonic in {"pop", "popq", "popl", "popw"}
            or opcode_without_encoding_prefix.startswith(
                (
                    "cld",
                    "clc",
                    "cmc",
                    "clrssbsy",
                    "enter",
                    "incssp",
                    "lahf",
                    "leave",
                    "pop ",
                    "popa",
                    "popf",
                    "push",
                    "rdssp",
                    "rstorssp",
                    "saveprevssp",
                    "sahf",
                    "setssbsy",
                    "stc",
                    "std",
                    "wrss",
                    "wruss",
                )
            )
        ):
            capability, reason = "stack_and_abi", "stack frame and ABI semantics were not proven"
        elif (
            opcode_without_encoding_prefix.startswith(
                (
                    "bnd",
                    "bound",
                    "clac",
                    "cldemote",
                    "clflush",
                    "clflushopt",
                    "clgi",
                    "clzero",
                    "clwb",
                    "cli",
                    "cpuid",
                    "enqcmd",
                    "enqcmds",
                    "endbr32",
                    "endbr64",
                    "encls",
                    "enclu",
                    "enclv",
                    "getsec",
                    "hlt",
                    "in ",
                    "invd",
                    "invept",
                    "invlpg",
                    "invlpga",
                    "invpcid",
                    "invvpid",
                    "insb",
                    "insd",
                    "insw",
                    "lar",
                    "lds",
                    "les",
                    "lgdt",
                    "lidt",
                    "lmsw",
                    "lldt",
                    "lsl",
                    "lss",
                    "ltr",
                    "mcommit",
                    "movdir64b",
                    "movdiri",
                    "out ",
                    "outsb",
                    "outsd",
                    "outsw",
                    "pcommit",
                    "pconfig",
                    "prefetch",
                    "psmash",
                    "ptwrite",
                    "pvalidate",
                    "rdmsr",
                    "rdpid",
                    "rdpkru",
                    "rdpmc",
                    "rdpru",
                    "rdrand",
                    "rdseed",
                    "rmpadjust",
                    "rmpupdate",
                    "rdtsc",
                    "rdtscp",
                    "rsm",
                    "seamcall",
                    "seamops",
                    "seamret",
                    "serialize",
                    "sgdt",
                    "sidt",
                    "skinit",
                    "sldt",
                    "smsw",
                    "stac",
                    "stgi",
                    "sti",
                    "str",
                    "tdcall",
                    "verr",
                    "verw",
                    "vmcall",
                    "vmclear",
                    "vmlaunch",
                    "vmload",
                    "vmmcall",
                    "vmfunc",
                    "vmptrld",
                    "vmptrst",
                    "vmread",
                    "vmresume",
                    "vmrun",
                    "vmsave",
                    "vmwrite",
                    "vmxon",
                    "vmxoff",
                    "wbnoinvd",
                    "wbinvd",
                    "xgetbv",
                    "xsetbv",
                    "wrmsr",
                    "wrpkru",
                )
            )
            or any(
                token in opcode
                for token in (
                    " cr0",
                    " cr1",
                    " cr2",
                    " cr3",
                    " cr4",
                    " cr8",
                    " dr0",
                    " dr1",
                    " dr2",
                    " dr3",
                    " dr6",
                    " dr7",
                )
            )
            or any(term in {"cs", "ds", "es", "ss"} for term in opcode_terms)
        ):
            capability, reason = "cpu_environment", "CPU environment semantics were not proven"
        elif (
            mnemonic.startswith(
                (
                    "f2xm1",
                    "fabs",
                    "fadd",
                    "fbld",
                    "fbstp",
                    "fcmov",
                    "fchs",
                    "fcom",
                    "fcos",
                    "fdecstp",
                    "fdiv",
                    "ffree",
                    "fiadd",
                    "ficom",
                    "fidiv",
                    "fild",
                    "fimul",
                    "fincstp",
                    "fist",
                    "fisub",
                    "fld",
                    "fmul",
                    "fnop",
                    "fpatan",
                    "fprem",
                    "fptan",
                    "frndint",
                    "fscale",
                    "fsin",
                    "fsqrt",
                    "fst",
                    "fsub",
                    "fucom",
                    "fxam",
                    "fxch",
                    "fxtract",
                    "fyl2x",
                )
            )
            or opcode_without_encoding_prefix.startswith(
                (
                    "emms",
                    "femms",
                    "fclex",
                    "finit",
                    "fldcw",
                    "fnclex",
                    "fninit",
                    "fnsave",
                    "fnstcw",
                    "fnstenv",
                    "fnstsw",
                    "frstor",
                    "fsave",
                    "fstcw",
                    "fstenv",
                    "fstsw",
                    "fwait",
                    "fxrstor",
                    "fxsave",
                    "ldmxcsr",
                    "ldtilecfg",
                    "stmxcsr",
                    "sttilecfg",
                    "tileloadd",
                    "tileloaddt1",
                    "tilerelease",
                    "tilestored",
                    "tilezero",
                    "vzero",
                    "wait",
                    "xrstor",
                    "xsave",
                )
            )
            or any(
                token in opcode
                for token in (
                    "xmm",
                    "ymm",
                    "zmm",
                    "mm0",
                    "mm1",
                    "mm2",
                    "mm3",
                    "mm4",
                    "mm5",
                    "mm6",
                    "mm7",
                    "k0",
                    "k1",
                    "k2",
                    "k3",
                    "k4",
                    "k5",
                    "k6",
                    "k7",
                    "tmm0",
                    "tmm1",
                    "tmm2",
                    "tmm3",
                    "tmm4",
                    "tmm5",
                    "tmm6",
                    "tmm7",
                    "st0",
                    "st1",
                    "st2",
                    "st3",
                    "st4",
                    "st5",
                    "st6",
                    "st7",
                )
            )
        ):
            capability, reason = "floating_point_and_simd", "floating-point or SIMD semantics were not proven"
        elif opcode_without_encoding_prefix.startswith(("cmps", "lods", "movs", "scas", "stos", "xlat")):
            capability, reason = (
                "memory_operands",
                "implicit memory operand semantics were not proven for whole-function virtualization",
            )
        elif "[" in opcode:
            capability, reason = (
                "memory_operands",
                "memory operand semantics were not proven for whole-function virtualization",
            )
        else:
            capability, reason = (
                "instruction_semantics",
                "instruction semantics were not proven for whole-function virtualization",
            )
        return capability, reason

    @staticmethod
    def _unsupported_record(
        func: dict[str, Any],
        instruction: dict[str, Any] | None,
        capability: str,
        reason: str,
        severity: str,
    ) -> dict[str, Any]:
        """Build a stable, actionable record for a rejected function."""
        instruction_data = instruction or {}
        instruction_size = instruction_data.get("size", 0)
        instruction_opcode = str(
            instruction_data.get("opcode") or instruction_data.get("disasm") or instruction_data.get("mnemonic") or ""
        )[:_MAX_DIAGNOSTIC_OPCODE_CHARS]
        instruction_address = instruction_data.get("addr", instruction_data.get("offset", func.get("addr", 0)))
        return {
            "function_address": int(func.get("addr", 0)),
            "instruction_address": int(instruction_address),
            "instruction_type": str(instruction_data.get("type", "")),
            "instruction_mnemonic": instruction_opcode.split(maxsplit=1)[0] if instruction_opcode else "",
            "instruction_opcode": instruction_opcode,
            "instruction_size": instruction_size if isinstance(instruction_size, int) and instruction_size > 0 else 0,
            "capability": capability,
            "reason": reason,
            "severity": severity,
        }

    def _record_diagnostic(
        self,
        records: list[dict[str, Any]],
        func: dict[str, Any],
        instruction: dict[str, Any] | None,
        diagnostic: tuple[str, str, str],
    ) -> None:
        """Keep actionable rejection evidence bounded per pass run."""
        severity, capability, reason = diagnostic
        if len(records) < _MAX_UNSUPPORTED_RECORDS:
            records.append(self._unsupported_record(func, instruction, capability, reason, severity))

    def _record_partial_virtualization(
        self,
        records: list[dict[str, Any]],
        func: dict[str, Any],
        instruction: dict[str, Any] | None,
        enabled: bool,
    ) -> int:
        """Record a warning when only a straight-line region was transformed."""
        if not enabled:
            return 0
        capability, reason = self._unsupported_instruction_diagnostic(instruction)
        self._record_diagnostic(
            records,
            func,
            instruction,
            (
                "warning",
                capability,
                f"only a straight-line region was proven; {reason}",
            ),
        )
        return 1

    def _record_unsupported_function(
        self,
        records: list[dict[str, Any]],
        func: dict[str, Any],
        instruction: dict[str, Any] | None,
        reason_prefix: str = "",
    ) -> None:
        """Record one bounded rejection with the best available capability."""
        capability, reason = self._unsupported_instruction_diagnostic(instruction)
        self._record_diagnostic(
            records,
            func,
            instruction,
            ("error", capability, f"{reason_prefix}{reason}"),
        )

    def _virtualize_fallback_run(
        self,
        binary: Any,
        func: dict[str, Any],
        unsupported_instruction: dict[str, Any] | None,
        partial_records: list[dict[str, Any]],
    ) -> tuple[dict[str, Any] | None, int]:
        """Virtualize one proven straight-line run, if a function has one."""
        try:
            blocks = binary.get_basic_blocks(func["addr"])
        except Exception as exc:
            logger.debug("Failed to get blocks for 0x%x: %s", func["addr"], exc)
            return None, 0
        for block in blocks:
            run = self._find_run(binary, block)
            if run is None:
                continue
            result = self._virtualize_run(binary, run)
            if result is not None:
                partial = self._record_partial_virtualization(partial_records, func, unsupported_instruction, True)
                return result, partial
        return None, 0

    def _build_region_payload(
        self,
        binary: Any,
        region: Any,
        rng: random.Random,
        use_nesting: bool,
        unwind_frame: Any | None = None,
    ) -> tuple[int, bytes, bytes, _UnwindPayload, bool] | None:
        complete_unwind = unwind_frame is not None
        if complete_unwind and not region_supports_unwind_contract(region, unwind_frame):
            return None
        blob_vaddr = predict_blob_vaddr(binary, allow_inline=not complete_unwind)
        if blob_vaddr is None:
            return None
        blob = None
        scheme: Any | None = None
        nested = False
        if use_nesting and self.vm_nesting_depth >= _MIN_NESTING_DEPTH and not complete_unwind:
            blob = build_nested_region_blob(region, blob_vaddr, rng, depth=self.vm_nesting_depth)
            nested = blob is not None
        if blob is None:
            scheme = build_region_scheme(region, rng)
            blob = build_region_blob(region, blob_vaddr, scheme)
        if blob is None:
            return None
        if complete_unwind:
            if scheme is None:
                raise RuntimeError("complete unwind payload was built without a region scheme")
            landing_pad_targets = region_entry_vaddrs(blob, blob_vaddr, region, scheme)
            unwind = _build_unwind_payload(blob, scheme, region, unwind_frame, landing_pad_targets or None)
            if unwind is None:
                return None
        else:
            unwind = _UnwindPayload(None, ())
        original_bytes = binary.read_bytes(region.entry_vaddr, _TRAMPOLINE_SIZE)
        if not original_bytes or len(original_bytes) != _TRAMPOLINE_SIZE:
            return None
        return (
            blob_vaddr,
            blob,
            bytes(original_bytes),
            unwind,
            nested,
        )

    def _build_unwind_metadata(self, blob_vaddr: int, blob: bytes, unwind: _UnwindPayload) -> bytes | None:
        if unwind.frame_size is None:
            return None
        metadata_vaddr = (blob_vaddr + len(blob) + _EH_FRAME_ALIGNMENT - 1) & ~(_EH_FRAME_ALIGNMENT - 1)
        if unwind.lsda_template is not None:
            lsda_call_sites = tuple(
                (blob_vaddr + start, blob_vaddr + end, landing_pad, action_index)
                for start, end, landing_pad, action_index in unwind.lsda_call_sites
            )
            return build_vm_eh_frame_with_lsda(
                VmEhFrameSpec(
                    blob_vaddr,
                    len(blob),
                    unwind.frame_size,
                    metadata_vaddr,
                    unwind.call_ranges,
                    unwind.lsda_template,
                    lsda_call_sites,
                    unwind.personality,
                )
            )
        return build_vm_eh_frame(blob_vaddr, len(blob), unwind.frame_size, metadata_vaddr, unwind.call_ranges)

    def _install_region_payload(
        self,
        binary: Any,
        region: Any,
        blob_vaddr: int,
        blob: bytes,
        unwind: _UnwindPayload,
    ) -> tuple[Any] | None:
        checkpoint = self._create_mutation_checkpoint("virtualize_function")
        unwind_metadata = self._build_unwind_metadata(blob_vaddr, blob, unwind)
        injected_vaddr = inject_blob(binary, blob, unwind_metadata=unwind_metadata)
        if injected_vaddr is None:
            return None
        if injected_vaddr != blob_vaddr:
            self._rollback_uncommitted(binary, checkpoint, reason="VM blob landed at an unexpected vaddr; aborting")
            return None
        relative = injected_vaddr - (region.entry_vaddr + _TRAMPOLINE_SIZE)
        trampoline = b"\xe9" + struct.pack("<i", relative)
        if not binary.write_bytes(region.entry_vaddr, trampoline):
            self._rollback_uncommitted(binary, checkpoint, reason="failed to write VM trampoline; aborting")
            return None
        return (checkpoint,)

    def _overwrite_region_body(self, binary: Any, region: Any, checkpoint: Any) -> bool:
        trampoline_end = region.entry_vaddr + _TRAMPOLINE_SIZE
        for address, size in region.body_ranges:
            fill_start = max(address, trampoline_end)
            fill_size = address + size - fill_start
            if fill_size <= 0:
                continue
            junk = bytes(random.randrange(256) for _ in range(fill_size))
            if not binary.write_bytes(fill_start, junk):
                self._rollback_uncommitted(binary, checkpoint, reason="failed to overwrite dead body; aborting")
                return False
        return True

    def _emit_region(
        self,
        binary: Any,
        func: dict[str, Any],
        region: Any,
        options: RegionOptions,
    ) -> dict[str, Any] | None:
        """Build the interpreter for a lowered region, inject it, patch the
        trampoline, and overwrite the dead body. Shared by the whole-function and
        dispatch paths; ``use_nesting`` requests the nested-layer blob."""
        payload = self._build_region_payload(binary, region, options.rng, options.use_nesting, options.unwind_frame)
        if payload is None:
            return None
        blob_vaddr, blob, original_bytes, unwind, nested = payload
        installed = self._install_region_payload(binary, region, blob_vaddr, blob, unwind)
        if installed is None:
            return None
        checkpoint = installed[0]
        if options.overwrite_body and not self._overwrite_region_body(binary, region, checkpoint):
            return None

        instruction_count = sum(1 for item in region.instructions if item[0] != "exit")
        record = self._record_mutation(
            function_address=func["addr"],
            start_address=region.entry_vaddr,
            end_address=region.entry_vaddr + _TRAMPOLINE_SIZE - 1,
            original_bytes=original_bytes,
            mutated_bytes=binary.read_bytes(region.entry_vaddr, _TRAMPOLINE_SIZE),
            original_disasm=f"; {instruction_count} instructions (control-flow region)",
            mutated_disasm=f"; trampoline -> VM ({len(blob)} bytes)",
            mutation_kind="code_virtualization",
            metadata={
                "instructions_count": instruction_count,
                "affected_instruction_mnemonics": sorted(
                    {str(item[0]) for item in region.instructions if item and isinstance(item[0], str)}
                ),
                "bytecode_size": len(blob),
                "nested_vm": nested,
                "landing_pad_entries": sorted(region.entry_map),
            },
        )
        if self._validate_mutation_or_rollback(binary, record, checkpoint):
            return None
        return {
            "blob_vaddr": blob_vaddr,
            "instructions": instruction_count,
            "bytecode": len(blob),
            "body_ranges": tuple(region.body_ranges),
        }

    def apply(self, binary: Any) -> dict[str, Any]:
        """Apply code virtualization to provable register runs."""
        return apply_code_virtualization(self, binary)
