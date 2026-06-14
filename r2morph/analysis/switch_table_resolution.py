"""Jump-table resolution helpers for switch table analysis."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.analysis.switch_table_models import IndirectJump, JumpTable, JumpTableEntry, JumpTableType
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def resolve_jump_table(
    binary: Binary,
    jump: IndirectJump,
    table_address: int | None = None,
    max_entries: int = 256,
) -> JumpTable | None:
    effective_address = table_address or jump.table_address or jump.displacement
    if effective_address is None or effective_address == 0:
        logger.debug("No table address for jump at 0x%x", jump.address)
        return None

    arch_info = binary.get_arch_info()
    bits = arch_info.get("bits", 64)
    ptr_size = bits // 8

    entries = read_jump_table_entries(binary, effective_address, ptr_size, bits, max_entries)
    if not entries:
        return None

    table_type = JumpTableType.DIRECT
    if jump.base_register and jump.index_register:
        table_type = JumpTableType.INDIRECT
    elif jump.scale != ptr_size:
        table_type = JumpTableType.COMPACT

    return JumpTable(
        table_address=effective_address,
        table_type=table_type,
        entries=entries,
        base_register=jump.base_register,
        scale=jump.scale,
        offset=jump.displacement,
        function_address=jump.function_address,
    )


def read_jump_table_entries(
    binary: Binary,
    effective_address: int,
    ptr_size: int,
    bits: int,
    max_entries: int,
) -> list[JumpTableEntry]:
    """Read pointer-sized targets from the table until a stop condition."""
    entries: list[JumpTableEntry] = []
    seen_targets: set[int] = set()

    try:
        offset = 0
        case_value = 0

        while len(entries) < max_entries:
            target_bytes = binary.read_bytes(effective_address + offset, ptr_size)
            if not target_bytes or len(target_bytes) != ptr_size:
                break

            target = int.from_bytes(target_bytes, "little", signed=False)
            if bits == 64 and target > 0x7FFFFFFFFFFF:
                target -= 1 << 64
            elif bits != 64 and target > 0x7FFFFFFF:
                target -= 1 << 32

            if target == 0 or target in seen_targets:
                break

            normalized = normalize_address(target, bits)
            entries.append(JumpTableEntry(index=len(entries), target_address=normalized, case_value=case_value))
            seen_targets.add(normalized)

            offset += ptr_size
            case_value += 1
    except Exception as e:
        logger.debug("Failed to read jump table at 0x%x: %s", effective_address, e)

    return entries


def normalize_address(addr: int, bits: int) -> int:
    """Normalize an address to valid range."""
    if bits == 64:
        if addr > 0xFFFFFFFFFFFFFFFF:
            addr = addr & 0xFFFFFFFFFFFFFFFF
        if addr > 0x7FFFFFFFFFFF:
            return 0
    else:
        addr = addr & 0xFFFFFFFF
        if addr > 0x7FFFFFFF:
            return 0
    return addr


def get_jump_table_targets(table: JumpTable) -> dict[int, list[int]]:
    """Map table indices to target addresses."""
    targets: dict[int, list[int]] = {}

    for entry in table.entries:
        if entry.case_value is None:
            continue

        case_value = entry.case_value
        target = entry.target_address

        if case_value not in targets:
            targets[case_value] = []
        targets[case_value].append(target)

    if table.default_case is not None and table.default_case not in targets:
        targets[table.default_case] = [0]

    return targets


def reconstruct_switch_cases(binary: Binary, table: JumpTable, function_address: int) -> dict[int, dict[str, Any]]:
    """Reconstruct switch case structure from jump table."""
    try:
        blocks = binary.get_basic_blocks(function_address)
    except Exception:
        return {}

    block_addrs = {b.get("addr", 0) for b in blocks}

    cases: dict[int, dict[str, Any]] = {}

    for entry in table.entries:
        if entry.is_default:
            continue

        target = entry.target_address
        case_value = entry.case_value if entry.case_value is not None else entry.index

        if target not in block_addrs:
            logger.debug(
                "Jump table entry %s targets 0x%x which is not a basic block start",
                entry.index,
                target,
            )

        cases[case_value] = {
            "value": case_value,
            "target": target,
            "is_block_start": target in block_addrs,
            "table_index": entry.index,
        }

    return cases
