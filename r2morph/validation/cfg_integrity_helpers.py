"""Helper routines for CFG integrity validation."""

from __future__ import annotations

from typing import Any

from r2morph.analysis.cfg import CFGBuilder
from r2morph.analysis.pattern_preservation import PatternPreservationManager, PatternType, PreservedPattern
from r2morph.validation.cfg_integrity_models import (
    CFGSnapshot,
    IntegrityCheck,
    IntegrityReport,
    IntegrityStatus,
    IntegrityViolation,
)


def create_cfg_snapshot(
    cfg_builder: CFGBuilder,
    preservation_manager: PatternPreservationManager | None,
    function_address: int,
) -> CFGSnapshot | None:
    """Build a CFG snapshot for a function."""
    try:
        func_name = f"func_{function_address:x}"
        cfg = cfg_builder.build_cfg(function_address, func_name)

        if not cfg or not cfg.blocks:
            return None

        blocks: dict[int, dict[str, Any]] = {}
        edges: list[tuple[int, int, str]] = []
        entry_block = None
        exit_blocks: list[int] = []

        for addr, block in cfg.blocks.items():
            block_info: dict[str, Any] = {
                "address": addr,
                "size": block.size if hasattr(block, "size") else 0,
                "instructions": [],
                "is_entry": getattr(block, "is_entry", False),
                "is_exit": getattr(block, "is_exit", False),
            }

            if hasattr(block, "instructions"):
                for insn in block.instructions:
                    block_info["instructions"].append(
                        {
                            "address": insn.get("offset", 0),
                            "mnemonic": insn.get("type", ""),
                            "disasm": insn.get("disasm", ""),
                        }
                    )

            blocks[addr] = block_info

            if block_info["is_entry"] and entry_block is None:
                entry_block = addr

            if block_info["is_exit"]:
                exit_blocks.append(addr)

        for src, dst in getattr(cfg, "edges", []):
            edges.append((src, dst, "normal"))

        for exc_edge in getattr(cfg, "exception_edges", []):
            edges.append((exc_edge.from_address, exc_edge.to_address, "exception"))

        preserved: list[PreservedPattern] = []
        if preservation_manager and preservation_manager._analyzed:
            preserved = preservation_manager.get_patterns_in_range(
                function_address,
                function_address + 0x10000,
            )

        return CFGSnapshot(
            function_address=function_address,
            blocks=blocks,
            edges=edges,
            entry_block=entry_block,
            exit_blocks=exit_blocks,
            preserved_patterns=preserved,
        )

    except Exception:
        return None


def validate_cfg_snapshot(snapshot: CFGSnapshot) -> IntegrityReport:
    """Validate a previously captured CFG snapshot."""
    report = IntegrityReport(valid=True)

    report.checks_run.append(
        IntegrityCheck(
            name="block_reachability",
            description="Verify all blocks in snapshot are still reachable",
        )
    )
    _check_reachability(snapshot, report)

    report.checks_run.append(
        IntegrityCheck(
            name="edge_preservation",
            description="Verify critical edges are preserved",
        )
    )
    _check_edge_preservation(snapshot, report)

    report.checks_run.append(
        IntegrityCheck(
            name="jump_target_validity",
            description="Verify all jump targets are valid",
        )
    )
    _check_jump_targets(snapshot, report)

    report.checks_run.append(
        IntegrityCheck(
            name="pattern_preservation",
            description="Verify preserved patterns are intact",
        )
    )
    _check_preserved_patterns(snapshot, report)

    report.valid = len(report.violations) == 0
    report.statistics = {
        "total_blocks": len(snapshot.blocks),
        "total_edges": len(snapshot.edges),
        "violation_count": len(report.violations),
        "checks_run": len(report.checks_run),
    }
    return report


def _check_reachability(snapshot: CFGSnapshot, report: IntegrityReport) -> None:
    if not snapshot.entry_block:
        return

    reachable = _compute_reachable(snapshot.entry_block, snapshot)
    for addr in snapshot.blocks:
        if addr not in reachable:
            report.violations.append(
                IntegrityViolation(
                    status=IntegrityStatus.UNREACHABLE,
                    address=addr,
                    description=f"Block at 0x{addr:x} is no longer reachable",
                    severity="warning",
                )
            )


def _compute_reachable(start: int, snapshot: CFGSnapshot) -> set[int]:
    reachable = set()
    stack = [start]

    while stack:
        addr = stack.pop()
        if addr in reachable:
            continue
        if addr not in snapshot.blocks:
            continue

        reachable.add(addr)
        for src, dst, _ in snapshot.edges:
            if src == addr and dst not in reachable:
                stack.append(dst)

    return reachable


def _check_edge_preservation(snapshot: CFGSnapshot, report: IntegrityReport) -> None:
    critical_types = {"exception", "unwind", "landing_pad"}

    for src, dst, edge_type in snapshot.edges:
        if edge_type in critical_types:
            if src not in snapshot.blocks:
                report.violations.append(
                    IntegrityViolation(
                        status=IntegrityStatus.BROKEN_EDGE,
                        address=src,
                        description=f"Critical edge source 0x{src:x} lost",
                        severity="error",
                        metadata={"edge_type": edge_type, "target": dst},
                    )
                )

            if dst not in snapshot.blocks:
                report.violations.append(
                    IntegrityViolation(
                        status=IntegrityStatus.BROKEN_EDGE,
                        address=dst,
                        description=f"Critical edge target 0x{dst:x} lost",
                        severity="error",
                        metadata={"edge_type": edge_type, "source": src},
                    )
                )


def _extract_jump_target(disasm: str) -> int | None:
    import re

    match = re.search(r"0x([0-9a-fA-F]+)", disasm)
    if match:
        try:
            return int(match.group(1), 16)
        except ValueError:
            pass
    return None


def _check_jump_targets(snapshot: CFGSnapshot, report: IntegrityReport) -> None:
    for addr, block_info in snapshot.blocks.items():
        instructions = block_info.get("instructions", [])
        for insn in instructions:
            mnemonic = insn.get("mnemonic", "").lower()
            disasm = insn.get("disasm", "")

            if mnemonic in ("jmp", "call", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"):
                target = _extract_jump_target(disasm)
                if target and target not in snapshot.blocks and target not in (0, snapshot.function_address):
                    report.violations.append(
                        IntegrityViolation(
                            status=IntegrityStatus.INVALID_TARGET,
                            address=insn.get("address", 0),
                            description=f"Jump target 0x{target:x} not in function",
                            severity="warning",
                            metadata={"instruction": disasm, "source_block": addr},
                        )
                    )


def _check_preserved_patterns(snapshot: CFGSnapshot, report: IntegrityReport) -> None:
    for pattern in snapshot.preserved_patterns:
        if pattern.start_address not in snapshot.blocks:
            addr_in_blocks = any(
                pattern.start_address <= block_addr < pattern.end_address for block_addr in snapshot.blocks
            )

            if not addr_in_blocks and pattern.type in (
                PatternType.EXCEPTION_HANDLER,
                PatternType.LANDING_PAD,
                PatternType.JUMP_TABLE,
                PatternType.PLT_THUNK,
            ):
                report.violations.append(
                    IntegrityViolation(
                        status=(
                            IntegrityStatus.JUMP_TABLE
                            if pattern.type == PatternType.JUMP_TABLE
                            else IntegrityStatus.EXCEPTION_FLOW
                        ),
                        address=pattern.start_address,
                        description=f"Preserved pattern {pattern.type.value} may be corrupted",
                        severity="error",
                        metadata={"pattern_type": pattern.type.value, "pattern_source": pattern.source},
                    )
                )
