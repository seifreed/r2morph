"""Gather and lower whole-function computed-dispatch regions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, cast

import r2morph.core.randomness as random
from r2morph.analysis.switch_table import SwitchTableAnalyzer
from r2morph.mutations.code_virtualization_region import extract_region

_MAX_DISPATCH_INSNS = 256
_MAX_DIRECT_BRANCH_TARGET_QUERIES = 64
_MEMORY_DISPATCH_KINDS = frozenset({"ijmpmem", "ijmpmemnb"})
_COMPUTED_SWITCH_KINDS = frozenset({"ujmp", "rjmp", "ijmp", "mjmp", "irjmp"})
_DIRECT_BRANCH_KINDS = frozenset({"jmp", "cjmp", "jrcxz"})
_BRANCH_PROBE_TERMINATORS = frozenset({"jmp", "rjmp", "ujmp", "ret", "swi", "syscall", "trap", "invalid"})
_MAX_FUNCTION_POINTER_TARGETS = 64
_TABLE_LOAD_PATTERN = re.compile(
    r"^mov\s+(?P<destination>[a-z0-9]+),\s*(?:qword\s+)?(?:ptr\s+)?"
    r"\[(?P<base>[a-z0-9]+)\s*\+\s*(?P<index>[a-z0-9]+)\s*\*\s*(?P<scale>[1248])\]$",
    re.IGNORECASE,
)
_LEA_PATTERN = re.compile(r"^lea\s+(?P<destination>[a-z0-9]+),", re.IGNORECASE)
_MASK_PATTERN = re.compile(r"^(?:and|cmp)\s+(?P<register>[a-z0-9]+),\s*(?P<value>0x[0-9a-f]+|[0-9]+)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class RegionOptions:
    """Build switches shared by ordinary and unwind-aware region lowering."""

    rng: random.Random
    use_nesting: bool
    unwind_frame: Any | None = None
    overwrite_body: bool = True


def _direct_branch_targets(ops: list[dict[str, Any]], function_range: tuple[int, int]) -> set[int]:
    start, end = function_range
    return {
        target
        for op in ops
        if op.get("type") in _DIRECT_BRANCH_KINDS
        and isinstance(target := op.get("jump"), int)
        and start <= target < end
    }


def _bounded_branch_probe(ops: object) -> list[dict[str, Any]]:
    """Keep only the linear block before an unconditional terminator."""
    if not isinstance(ops, list):
        return []
    bounded: list[dict[str, Any]] = []
    for op in ops:
        if not isinstance(op, dict):
            continue
        bounded.append(op)
        if op.get("type") in _BRANCH_PROBE_TERMINATORS:
            break
    return bounded


def _table_entry_count(ops: list[dict[str, Any]], index_register: str, end: int) -> int:
    """Infer a bounded pointer-table length from a preceding index guard."""
    for operation in reversed(ops[:end]):
        match = _MASK_PATTERN.match(str(operation.get("opcode", "")).strip())
        if match is None or match.group("register").lower() != index_register.lower():
            continue
        value = int(match.group("value"), 0)
        return min(value + 1, _MAX_FUNCTION_POINTER_TARGETS)
    return _MAX_FUNCTION_POINTER_TARGETS


def _dispatch_table_candidate(ops: list[dict[str, Any]]) -> tuple[int, int] | None:
    """Find a RIP-relative pointer table feeding a computed jump."""
    for jump_index, operation in enumerate(ops):
        if operation.get("type") not in _COMPUTED_SWITCH_KINDS:
            continue
        for load_index in range(jump_index - 1, -1, -1):
            load = _TABLE_LOAD_PATTERN.match(str(ops[load_index].get("opcode", "")).strip())
            if load is None:
                continue
            base_register = load.group("base")
            for setup in reversed(ops[:load_index]):
                lea = _LEA_PATTERN.match(str(setup.get("opcode", "")).strip())
                if lea is None or lea.group("destination").lower() != base_register.lower():
                    continue
                table_address = setup.get("ptr")
                if isinstance(table_address, int) and table_address > 0:
                    return table_address, _table_entry_count(ops, load.group("index"), load_index)
                break
    return None


def _executable_ranges(binary: Any) -> tuple[tuple[int, int], ...]:
    try:
        sections = binary.get_sections()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return ()
    ranges: list[tuple[int, int]] = []
    for section in sections:
        permission = str(section.get("perm", ""))
        start = section.get("vaddr", section.get("addr"))
        size = section.get("vsize", section.get("size"))
        if "x" in permission and isinstance(start, int) and isinstance(size, int) and size > 0:
            ranges.append((start, start + size))
    return tuple(ranges)


def _target_ops(binary: Any, target: int, executable_ranges: tuple[tuple[int, int], ...]) -> list[dict[str, Any]]:
    """Read one table target through its first return, within executable code."""
    if executable_ranges and not any(start <= target < end for start, end in executable_ranges):
        return []
    try:
        ops = binary.r2.cmdj(f"pdj {_MAX_DISPATCH_INSNS} @ {target}") or []
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return []
    return _bounded_branch_probe(ops) if any(operation.get("type") == "ret" for operation in ops) else []


def _append_function_pointer_targets(binary: Any, ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Append every proven local target of a bounded function-pointer table."""
    candidate = _dispatch_table_candidate(ops)
    if candidate is None:
        return ops
    table_address, entry_count = candidate
    pointer_size = int(binary.get_arch_info().get("bits", 64)) // 8
    if pointer_size not in (4, 8):
        return ops
    known_addresses = {operation.get("addr") for operation in ops}
    executable_ranges = _executable_ranges(binary)
    extended = list(ops)
    for index in range(entry_count):
        raw_target = binary.read_bytes(table_address + index * pointer_size, pointer_size)
        if len(raw_target) != pointer_size:
            break
        target = int.from_bytes(raw_target, "little")
        if target == 0:
            break
        target_instructions = _target_ops(binary, target, executable_ranges)
        if not target_instructions:
            continue
        for instruction in target_instructions:
            address = instruction.get("addr")
            if address not in known_addresses:
                extended.append(instruction)
                known_addresses.add(address)
    return extended


def complete_direct_branch_ops(
    binary: Any, ops: list[dict[str, Any]], function_range: tuple[int, int] | None
) -> list[dict[str, Any]]:
    """Fill missing in-range direct branch targets from bounded disassembly reads."""
    if function_range is None:
        return ops

    ops_by_addr = {
        op["addr"]: op
        for op in ops
        if isinstance(op.get("addr"), int) and function_range[0] <= op["addr"] < function_range[1]
    }
    pending = _direct_branch_targets(list(ops_by_addr.values()), function_range)
    queried: set[int] = set()
    # ponytail: cap target probes; a malformed CFG must not turn one function into an unbounded scan.
    while pending and len(queried) < _MAX_DIRECT_BRANCH_TARGET_QUERIES:
        target = pending.pop()
        if target in queried:
            continue
        queried.add(target)
        try:
            target_ops = binary.r2.cmdj(f"pdj {_MAX_DISPATCH_INSNS} @ {target}") or []
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            continue
        for op in _bounded_branch_probe(target_ops):
            address = op.get("addr")
            if (
                isinstance(address, int)
                and function_range[0] <= address < function_range[1]
                and address not in ops_by_addr
            ):
                ops_by_addr[address] = op
        pending.update(_direct_branch_targets(list(ops_by_addr.values()), function_range) - queried)

    return [ops_by_addr[address] for address in sorted(ops_by_addr)]


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
            return _append_function_pointer_targets(binary, gathered)
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
    rng = owner._rng_for_address(int(func["addr"]))
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
