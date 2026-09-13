"""Gather and lower whole-function computed-dispatch regions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import r2morph.core.randomness as random
from r2morph.analysis.switch_table import SwitchTableAnalyzer
from r2morph.mutations.code_virtualization_region import extract_region

_MAX_DISPATCH_INSNS = 256
_MEMORY_DISPATCH_KINDS = frozenset({"ijmpmem", "ijmpmemnb"})
_COMPUTED_SWITCH_KINDS = frozenset({"ujmp", "rjmp", "ijmp", "mjmp", "irjmp"})


@dataclass(frozen=True, slots=True)
class RegionOptions:
    """Build switches shared by ordinary and unwind-aware region lowering."""

    rng: random.Random
    use_nesting: bool
    unwind_frame: Any | None = None


def gather_dispatch_ops(binary: Any, func: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Read a dispatch-shaped function linearly through its first terminator."""
    try:
        ops = binary.r2.cmdj(f"pdj {_MAX_DISPATCH_INSNS} @ {func['addr']}")
    except Exception:
        return None
    if not ops:
        return None
    gathered: list[dict[str, Any]] = []
    for insn in ops:
        if insn.get("type") == "invalid" or insn.get("opcode") == "invalid":
            break
        gathered.append(insn)
        if insn.get("type") in ("ret", "swi", "syscall"):
            return gathered
    return None


def reachable_blocks(by_addr: dict[int, dict[str, Any]], entry: int) -> set[int]:
    """Follow static and already-resolved switch edges from a function entry."""
    reachable: set[int] = set()
    work = [entry]
    while work:
        addr = work.pop()
        if addr in reachable or addr not in by_addr:
            continue
        reachable.add(addr)
        block = by_addr[addr]
        successors: list[Any] = [block.get("jump"), block.get("fail")]
        switch_op = block.get("switch_op")
        if isinstance(switch_op, dict):
            successors.extend(case.get("jump") for case in switch_op.get("cases", []))
            successors.append(switch_op.get("def_val"))
        work.extend(successor for successor in successors if isinstance(successor, int) and successor in by_addr)
    return reachable


def block_ops(binary: Any, entry: int, by_addr: dict[int, dict[str, Any]], reachable: set[int]) -> list[dict[str, Any]]:
    """Materialize instructions from all reachable blocks."""
    ranges = [(by_addr[addr]["addr"], by_addr[addr]["addr"] + by_addr[addr].get("size", 0)) for addr in reachable]

    def in_reachable(addr: int) -> bool:
        return any(start <= addr < end for start, end in ranges)

    ops_by_addr: dict[int, dict[str, Any]] = {}
    for op in binary.get_function_disasm(entry):
        addr = op.get("addr")
        if isinstance(addr, int) and in_reachable(addr):
            ops_by_addr[addr] = op
    for start, end in ranges:
        if any(start <= addr < end for addr in ops_by_addr):
            continue
        for op in binary.r2.cmdj(f"pdbj @ {start}") or []:
            addr = op.get("addr")
            if isinstance(addr, int) and start <= addr < end:
                ops_by_addr[addr] = op
    return [ops_by_addr[addr] for addr in sorted(ops_by_addr)]


def _has_resolved_switch_marker(ops: list[dict[str, Any]]) -> bool:
    for op in ops:
        if op.get("type") not in _COMPUTED_SWITCH_KINDS:
            continue
        flags = op.get("flags")
        if isinstance(flags, list) and any(str(flag).startswith("switch.") for flag in flags):
            return True
    return False


def gather_cfg_ops(binary: Any, func: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Gather a complete function only when r2 resolved a switch edge set."""
    entry = func["addr"]
    try:
        blocks = binary.get_basic_blocks(entry)
    except Exception:
        return None
    by_addr = {block["addr"]: block for block in blocks if isinstance(block.get("addr"), int)}
    if entry not in by_addr:
        return None
    reachable = reachable_blocks(by_addr, entry)
    if not any(isinstance(by_addr[addr].get("switch_op"), dict) for addr in reachable):
        fallback_ops = gather_dispatch_ops(binary, func)
        return fallback_ops if fallback_ops is not None and _has_resolved_switch_marker(fallback_ops) else None
    ops = block_ops(binary, entry, by_addr, reachable)
    return ops or None


def _dispatch_table_address(item: tuple[Any, ...]) -> int | None:
    if item[0] == "ijmpmem":
        return int(item[4])
    if item[0] == "ijmpmemnb":
        return int(item[3])
    return None


def _memory_dispatch_targets(binary: Any, function_address: int, region: Any) -> bool:
    """Prove every resolved memory-dispatch target is inside the VM region."""
    tables, _other_jumps = SwitchTableAnalyzer(binary).detect_switch_pattern(function_address)
    targets_by_table = {
        table.table_address: {entry.target_address for entry in table.entries}
        for table in tables
        if table.table_address is not None
    }
    for item in region.instructions:
        if item[0] not in _MEMORY_DISPATCH_KINDS:
            continue
        table_address = _dispatch_table_address(item)
        if table_address is None:
            return False
        targets = targets_by_table.get(table_address)
        if not targets or not targets.issubset(region.target_map):
            return False
    return True


def virtualize_dispatch_function(
    owner: Any, binary: Any, func: dict[str, Any], unwind_frame: Any | None = None
) -> dict[str, Any] | None:
    """Virtualize a dispatch-shaped function through the region VM."""
    cfg_ops = gather_cfg_ops(binary, func)
    ops = cfg_ops if cfg_ops is not None else gather_dispatch_ops(binary, func)
    if ops is None:
        return None
    rng = random.Random(random.getrandbits(64))
    region = extract_region(ops, rng, allow_computed_jump=True)
    if region is None:
        return None
    computed = {item[0] for item in region.instructions} & {"ijmp", "ijmpmem", "ijmpmemnb"}
    if not computed:
        return None
    # A memory-indirect switch needs every resolved case target in the VM map. r2 may
    # stop CFG analysis at a computed jump, so a complete static table is sufficient.
    if (
        cfg_ops is None
        and computed & _MEMORY_DISPATCH_KINDS
        and not _memory_dispatch_targets(binary, func["addr"], region)
    ):
        return None
    return cast(
        dict[str, Any] | None,
        owner._emit_region(binary, func, region, RegionOptions(rng, False, unwind_frame)),
    )
