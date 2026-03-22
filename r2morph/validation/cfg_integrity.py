"""
CFG Integrity validation for complex binary transformations.

Validates that control flow graph integrity is preserved after mutations:
- Reachability checks
- Critical edge preservation
- Jump target validity
- Exception handling flow
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary
from r2morph.analysis.cfg import CFGBuilder
from r2morph.analysis.pattern_preservation import (
    PatternPreservationManager,
    PatternType,
    PreservedPattern,
)

logger = logging.getLogger(__name__)


class IntegrityStatus(Enum):
    VALID = "valid"
    BROKEN_EDGE = "broken_edge"
    UNREACHABLE = "unreachable"
    INVALID_TARGET = "invalid_target"
    EXCEPTION_FLOW = "exception_flow"
    JUMP_TABLE = "jump_table"
    PLT_THUNK = "plt_thunk"


@dataclass
class IntegrityViolation:
    status: IntegrityStatus
    address: int
    description: str
    severity: str = "error"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "address": f"0x{self.address:x}",
            "description": self.description,
            "severity": self.severity,
            "metadata": self.metadata,
        }


@dataclass
class IntegrityCheck:
    name: str
    description: str
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
        }


@dataclass
class IntegrityReport:
    valid: bool
    violations: list[IntegrityViolation] = field(default_factory=list)
    checks_run: list[IntegrityCheck] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "violations": [v.to_dict() for v in self.violations],
            "checks_run": [c.to_dict() for c in self.checks_run],
            "statistics": self.statistics,
        }


@dataclass
class CFGSnapshot:
    function_address: int
    blocks: dict[int, dict[str, Any]]
    edges: list[tuple[int, int, str]]
    entry_block: int | None = None
    exit_blocks: list[int] = field(default_factory=list)
    preserved_patterns: list[PreservedPattern] = field(default_factory=list)


class CFGIntegrityChecker:
    """
    Validates CFG integrity after mutations.

    Takes snapshots before mutation and validates after to ensure
    critical control flow properties are preserved.
    """

    def __init__(self, binary: Binary, preserve_patterns: bool = True) -> None:
        self.binary = binary
        self.preserve_patterns = preserve_patterns
        self._snapshots: dict[int, CFGSnapshot] = {}
        self._preservation_manager: PatternPreservationManager | None = None
        self._cfg_builder = CFGBuilder(binary)

    def create_snapshot(self, function_address: int) -> CFGSnapshot | None:
        """
        Create a CFG snapshot for a function before mutation.

        Args:
            function_address: Function address

        Returns:
            CFGSnapshot or None if failed
        """
        try:
            func_name = f"func_{function_address:x}"
            cfg = self._cfg_builder.build_cfg(function_address, func_name)

            if not cfg or not cfg.blocks:
                logger.debug(f"Empty CFG for 0x{function_address:x}")
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

            if hasattr(cfg, "edges"):
                for edge in cfg.edges:
                    src = edge[0] if hasattr(edge, "src") else edge[0]
                    dst = edge[1] if hasattr(edge, "dst") else edge[1]
                    edge_type = (
                        getattr(edge, "type", "") if hasattr(edge, "type") else edge[2] if len(edge) > 2 else "normal"
                    )
                    edges.append((src, dst, edge_type))

            preserved: list[PreservedPattern] = []
            if self._preservation_manager and self._preservation_manager._analyzed:
                preserved = self._preservation_manager.get_patterns_in_range(
                    function_address,
                    function_address + 0x10000,
                )

            snapshot = CFGSnapshot(
                function_address=function_address,
                blocks=blocks,
                edges=edges,
                entry_block=entry_block,
                exit_blocks=exit_blocks,
                preserved_patterns=preserved,
            )

            self._snapshots[function_address] = snapshot
            return snapshot

        except Exception as e:
            logger.debug(f"Failed to create snapshot for 0x{function_address:x}: {e}")
            return None

    def validate_integrity(self, function_address: int) -> IntegrityReport:
        """
        Validate CFG integrity after mutation.

        Args:
            function_address: Function address

        Returns:
            IntegrityReport with validation results
        """
        snapshot = self._snapshots.get(function_address)

        if not snapshot:
            return IntegrityReport(
                valid=False,
                violations=[
                    IntegrityViolation(
                        status=IntegrityStatus.INVALID_TARGET,
                        address=function_address,
                        description="No snapshot found for function",
                        severity="error",
                    )
                ],
            )

        report = IntegrityReport(valid=True)

        report.checks_run.append(
            IntegrityCheck(
                name="block_reachability",
                description="Verify all blocks in snapshot are still reachable",
            )
        )
        self._check_reachability(snapshot, report)

        report.checks_run.append(
            IntegrityCheck(
                name="edge_preservation",
                description="Verify critical edges are preserved",
            )
        )
        self._check_edge_preservation(snapshot, report)

        report.checks_run.append(
            IntegrityCheck(
                name="jump_target_validity",
                description="Verify all jump targets are valid",
            )
        )
        self._check_jump_targets(snapshot, report)

        report.checks_run.append(
            IntegrityCheck(
                name="pattern_preservation",
                description="Verify preserved patterns are intact",
            )
        )
        self._check_preserved_patterns(snapshot, report)

        report.valid = len(report.violations) == 0

        report.statistics = {
            "total_blocks": len(snapshot.blocks),
            "total_edges": len(snapshot.edges),
            "violation_count": len(report.violations),
            "checks_run": len(report.checks_run),
        }

        return report

    def _check_reachability(self, snapshot: CFGSnapshot, report: IntegrityReport) -> None:
        """Check that all blocks from snapshot are still reachable."""
        if not snapshot.entry_block:
            return

        reachable = self._compute_reachable(snapshot.entry_block, snapshot)

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

    def _compute_reachable(self, start: int, snapshot: CFGSnapshot) -> set[int]:
        """Compute reachable blocks from start address."""
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

    def _check_edge_preservation(self, snapshot: CFGSnapshot, report: IntegrityReport) -> None:
        """Check that critical edges are preserved."""
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

    def _check_jump_targets(self, snapshot: CFGSnapshot, report: IntegrityReport) -> None:
        """Check that jump targets are valid."""
        for addr, block_info in snapshot.blocks.items():
            instructions = block_info.get("instructions", [])

            for insn in instructions:
                mnemonic = insn.get("mnemonic", "").lower()
                disasm = insn.get("disasm", "")

                if mnemonic in ("jmp", "call", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"):
                    target = self._extract_jump_target(disasm)
                    if target and target not in snapshot.blocks:
                        if target not in (0, snapshot.function_address):
                            report.violations.append(
                                IntegrityViolation(
                                    status=IntegrityStatus.INVALID_TARGET,
                                    address=insn.get("address", 0),
                                    description=f"Jump target 0x{target:x} not in function",
                                    severity="warning",
                                    metadata={
                                        "instruction": disasm,
                                        "source_block": addr,
                                    },
                                )
                            )

    def _extract_jump_target(self, disasm: str) -> int | None:
        """Extract jump target from disassembly."""
        import re

        match = re.search(r"0x([0-9a-fA-F]+)", disasm)
        if match:
            try:
                return int(match.group(1), 16)
            except ValueError:
                pass
        return None

    def _check_preserved_patterns(self, snapshot: CFGSnapshot, report: IntegrityReport) -> None:
        """Check that preserved patterns are intact."""
        for pattern in snapshot.preserved_patterns:
            if pattern.start_address not in snapshot.blocks:
                addr_in_blocks = any(
                    pattern.start_address <= block_addr < pattern.end_address for block_addr in snapshot.blocks
                )

                if not addr_in_blocks:
                    if pattern.type in (
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

    def analyze_preservation_before(
        self,
        function_address: int,
    ) -> dict[str, Any] | None:
        """
        Analyze patterns that need preservation before mutation.

        Args:
            function_address: Function address

        Returns:
            Dictionary with preservation analysis
        """
        if self._preservation_manager is None:
            self._preservation_manager = PatternPreservationManager(self.binary)
            self._preservation_manager.analyze()

        patterns = self._preservation_manager.get_patterns_in_range(
            function_address,
            function_address + 0x10000,
        )

        zones = self._preservation_manager.get_exclusion_zones()

        func_zones = [
            z for z in zones if z.expanded_start < function_address + 0x10000 and z.expanded_end > function_address
        ]

        return {
            "function_address": function_address,
            "patterns_detected": len(patterns),
            "patterns": [p.to_dict() for p in patterns],
            "exclusion_zones": [z.to_dict() for z in func_zones],
            "safe_regions": self._preservation_manager.get_safe_addresses(
                function_address,
                function_address + 0x10000,
            ),
        }

    def clear_snapshot(self, function_address: int) -> None:
        """Clear a snapshot after validation."""
        if function_address in self._snapshots:
            del self._snapshots[function_address]

    def clear_all_snapshots(self) -> None:
        """Clear all stored snapshots."""
        self._snapshots.clear()


class HardenedMutationValidator:
    """
    Combined validator for hardened mutations.

    Combines pattern preservation and CFG integrity checks.
    """

    def __init__(self, binary: Binary) -> None:
        self.binary = binary
        self._preservation_manager: PatternPreservationManager | None = None
        self._integrity_checker = CFGIntegrityChecker(binary)

    def pre_mutation_analysis(self, function_address: int) -> dict[str, Any]:
        """
        Perform pre-mutation analysis.

        Args:
            function_address: Function address

        Returns:
            Pre-mutation analysis results
        """
        if self._preservation_manager is None:
            self._preservation_manager = PatternPreservationManager(self.binary)
            self._preservation_manager.analyze()

        snapshot = self._integrity_checker.create_snapshot(function_address)

        preservation = self._preservation_manager.get_patterns_in_range(
            function_address,
            function_address + 0x10000,
        )

        safe_addresses = self._preservation_manager.get_safe_addresses(
            function_address,
            function_address + 0x10000,
        )

        return {
            "function_address": function_address,
            "snapshot_created": snapshot is not None,
            "patterns_to_preserve": len(preservation),
            "safe_address_ranges": len(safe_addresses),
            "exclusion_zones": len(
                [z for z in self._preservation_manager.get_exclusion_zones() if z.expanded_start >= function_address]
            ),
        }

    def post_mutation_validation(self, function_address: int) -> dict[str, Any]:
        """
        Perform post-mutation validation.

        Args:
            function_address: Function address

        Returns:
            Validation results
        """
        integrity_report = self._integrity_checker.validate_integrity(function_address)

        result = {
            "function_address": function_address,
            "valid": integrity_report.valid,
            "violations": len(integrity_report.violations),
            "violation_details": [v.to_dict() for v in integrity_report.violations],
            "checks_run": len(integrity_report.checks_run),
        }

        self._integrity_checker.clear_snapshot(function_address)

        return result

    def get_preservation_manager(self) -> PatternPreservationManager:
        """Get the preservation manager."""
        if self._preservation_manager is None:
            self._preservation_manager = PatternPreservationManager(self.binary)
            self._preservation_manager.analyze()
        return self._preservation_manager
