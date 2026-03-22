"""
Critical node detection for CFG-aware mutations.

Identifies critical control flow points that should not be mutated:
- Branch targets
- Call sites
- Entry/exit points
- Exception handlers
- Loop headers
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from r2morph.analysis.cfg import ControlFlowGraph, BlockType

logger = logging.getLogger(__name__)


@dataclass
class AddressRange:
    """Represents a range of addresses."""

    start: int
    end: int

    def __contains__(self, address: int) -> bool:
        """Check if address is within this range."""
        return self.start <= address <= self.end

    def overlaps(self, other: "AddressRange") -> bool:
        """Check if this range overlaps with another."""
        return self.start <= other.end and other.start <= self.end

    def merge(self, other: "AddressRange") -> "AddressRange":
        """Merge this range with another."""
        return AddressRange(
            start=min(self.start, other.start),
            end=max(self.end, other.end),
        )

    def size(self) -> int:
        """Get the size of this range."""
        return self.end - self.start + 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "size": self.size(),
        }


@dataclass
class CriticalNode:
    """Represents a critical node in the CFG."""

    address: int
    node_type: str
    reason: str
    exclusion_radius: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": f"0x{self.address:x}",
            "type": self.node_type,
            "reason": self.reason,
            "exclusion_radius": self.exclusion_radius,
        }


class CriticalNodeDetector:
    """
    Detects critical nodes in a control flow graph.

    Critical nodes are control flow points that should be protected
    during mutations to avoid breaking program semantics.

    Usage:
        detector = CriticalNodeDetector(cfg)
        critical = detector.find_all_critical_nodes()
        exclusion_zones = detector.get_exclusion_zones()
        safe_regions = detector.get_safe_regions()
    """

    def __init__(self, cfg: ControlFlowGraph, default_exclusion_radius: int = 3):
        """
        Initialize critical node detector.

        Args:
            cfg: Control flow graph to analyze
            default_exclusion_radius: Default number of instructions to exclude
                                      around critical nodes
        """
        self.cfg = cfg
        self.default_exclusion_radius = default_exclusion_radius
        self._critical_nodes: dict[int, CriticalNode] = {}
        self._exclusion_zones: list[AddressRange] = []
        self._safe_regions: list[AddressRange] = []

    def find_all_critical_nodes(self) -> dict[int, CriticalNode]:
        """
        Find all critical nodes in the CFG.

        Returns:
            Dictionary mapping addresses to CriticalNode instances
        """
        self._critical_nodes.clear()

        branch_targets = self.find_branch_targets()
        for addr in branch_targets:
            self._critical_nodes[addr] = CriticalNode(
                address=addr,
                node_type="branch_target",
                reason="Target of a branch instruction",
                exclusion_radius=self.default_exclusion_radius,
            )

        call_sites = self.find_call_sites()
        for addr in call_sites:
            self._critical_nodes[addr] = CriticalNode(
                address=addr,
                node_type="call_site",
                reason="Call instruction site",
                exclusion_radius=self.default_exclusion_radius,
            )

        entry_exits = self.find_entry_exits()
        for addr in entry_exits:
            self._critical_nodes[addr] = CriticalNode(
                address=addr,
                node_type="entry_exit",
                reason="Function entry or exit point",
                exclusion_radius=self.default_exclusion_radius + 2,
            )

        exception_handlers = self.find_exception_handlers()
        for addr in exception_handlers:
            self._critical_nodes[addr] = CriticalNode(
                address=addr,
                node_type="exception_handler",
                reason="Exception handling code",
                exclusion_radius=self.default_exclusion_radius + 1,
            )

        loop_headers = self.find_loop_headers()
        for addr in loop_headers:
            self._critical_nodes[addr] = CriticalNode(
                address=addr,
                node_type="loop_header",
                reason="Loop header block",
                exclusion_radius=self.default_exclusion_radius,
            )

        back_edges = self.find_back_edges()
        for from_addr, to_addr in back_edges:
            if from_addr not in self._critical_nodes:
                self._critical_nodes[from_addr] = CriticalNode(
                    address=from_addr,
                    node_type="back_edge",
                    reason="Source of loop back edge",
                    exclusion_radius=self.default_exclusion_radius,
                )

        return self._critical_nodes

    def find_branch_targets(self) -> set[int]:
        """
        Find all branch targets in the CFG.

        Returns:
            Set of addresses that are targets of branch instructions
        """
        targets: set[int] = set()

        for from_addr, to_addr in self.cfg.edges:
            targets.add(to_addr)

        for addr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                jump_target = insn.get("jump")
                if jump_target and isinstance(jump_target, int):
                    targets.add(jump_target)

        return targets

    def find_call_sites(self) -> set[int]:
        """
        Find all call instruction sites in the CFG.

        Returns:
            Set of addresses containing call instructions
        """
        call_sites: set[int] = set()

        for addr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                insn_type = insn.get("type", "").lower()
                if insn_type == "call":
                    call_sites.add(insn.get("offset", addr))

                disasm = insn.get("disasm", "").lower()
                if disasm.startswith("call"):
                    call_sites.add(insn.get("offset", addr))

        return call_sites

    def find_entry_exits(self) -> set[int]:
        """
        Find function entry and exit points.

        Returns:
            Set of entry and exit addresses
        """
        entry_exits: set[int] = set()

        if self.cfg.entry_block:
            entry_exits.add(self.cfg.entry_block.address)

        for addr, block in self.cfg.blocks.items():
            if block.block_type == BlockType.RETURN:
                entry_exits.add(addr)

            if len(block.successors) == 0 and block.block_type != BlockType.RETURN:
                entry_exits.add(addr)

        return entry_exits

    def find_exception_handlers(self) -> set[int]:
        """
        Find exception handler addresses.

        Returns:
            Set of exception handler addresses
        """
        handlers: set[int] = set()

        for edge in self.cfg.exception_edges:
            if edge.to_address:
                handlers.add(edge.to_address)

        for addr, block in self.cfg.blocks.items():
            if block.block_type == BlockType.EXCEPTION_HANDLER:
                handlers.add(addr)
            if block.block_type == BlockType.LANDING_PAD:
                handlers.add(addr)
            if block.metadata.get("is_landing_pad"):
                handlers.add(addr)

        return handlers

    def find_loop_headers(self) -> set[int]:
        """
        Find loop header blocks.

        Returns:
            Set of loop header addresses
        """
        loop_headers: set[int] = set()

        loops = self.cfg.find_loops()

        for from_addr, to_addr in loops:
            loop_headers.add(to_addr)

        dominators = self.cfg.compute_dominators()
        for from_addr, to_addr in self.cfg.edges:
            if to_addr in dominators.get(from_addr, set()):
                loop_headers.add(to_addr)

        return loop_headers

    def find_back_edges(self) -> list[tuple[int, int]]:
        """
        Find back edges in the CFG (edges that create loops).

        Returns:
            List of (from_addr, to_addr) tuples for back edges
        """
        return self.cfg.find_loops()

    def get_exclusion_zones(self) -> list[AddressRange]:
        """
        Get exclusion zones around critical nodes.

        Returns:
            List of AddressRange instances representing zones to avoid
        """
        if self._exclusion_zones:
            return self._exclusion_zones

        ranges: list[AddressRange] = []

        for addr, node in self._critical_nodes.items():
            radius = node.exclusion_radius
            start = addr - (radius * 4)
            end = addr + (radius * 4)

            block = self.cfg.get_block(addr)
            if block:
                start = max(start, block.address)
                end = min(end, block.address + block.size - 1)

            ranges.append(AddressRange(start=start, end=end))

        ranges.sort(key=lambda r: r.start)

        merged: list[AddressRange] = []
        for r in ranges:
            if merged and merged[-1].overlaps(r):
                merged[-1] = merged[-1].merge(r)
            else:
                merged.append(r)

        self._exclusion_zones = merged
        return self._exclusion_zones

    def get_safe_regions(self) -> list[AddressRange]:
        """
        Get safe regions for mutations (regions not in exclusion zones).

        Returns:
            List of AddressRange instances representing safe mutation zones
        """
        if self._safe_regions:
            return self._safe_regions

        if not self._exclusion_zones:
            self.get_exclusion_zones()

        all_blocks = sorted(
            [(addr, block) for addr, block in self.cfg.blocks.items()],
            key=lambda x: x[0],
        )

        safe: list[AddressRange] = []

        for addr, block in all_blocks:
            block_start = addr
            block_end = addr + block.size - 1

            in_exclusion = False
            for zone in self._exclusion_zones:
                if zone.overlaps(AddressRange(start=block_start, end=block_end)):
                    in_exclusion = True
                    break

            if not in_exclusion:
                safe.append(AddressRange(start=block_start, end=block_end))

        self._safe_regions = safe
        return self._safe_regions

    def is_critical(self, address: int) -> bool:
        """
        Check if an address is critical.

        Args:
            address: Address to check

        Returns:
            True if address is a critical node
        """
        return address in self._critical_nodes

    def is_in_exclusion_zone(self, address: int) -> bool:
        """
        Check if an address is in an exclusion zone.

        Args:
            address: Address to check

        Returns:
            True if address should be excluded from mutations
        """
        if not self._exclusion_zones:
            self.get_exclusion_zones()

        for zone in self._exclusion_zones:
            if address in zone:
                return True

        return False

    def get_critical_type(self, address: int) -> str | None:
        """
        Get the type of critical node at an address.

        Args:
            address: Address to check

        Returns:
            Critical node type or None if not critical
        """
        node = self._critical_nodes.get(address)
        return node.node_type if node else None

    def get_nearby_critical_nodes(self, address: int, radius: int = 16) -> list[CriticalNode]:
        """
        Get critical nodes near an address.

        Args:
            address: Center address
            radius: Byte radius to search

        Returns:
            List of nearby CriticalNode instances
        """
        nearby: list[CriticalNode] = []

        for addr, node in self._critical_nodes.items():
            if abs(addr - address) <= radius:
                nearby.append(node)

        return nearby


class MutationSafetyScorer:
    """
    Scores addresses for mutation safety based on CFG and data flow.

    Usage:
        scorer = MutationSafetyScorer()
        score = scorer.score_address(address, cfg, dataflow)
        safest = scorer.get_safest_addresses(cfg, count=10)
    """

    def __init__(self) -> None:
        self._detector: CriticalNodeDetector | None = None

    def score_address(
        self,
        address: int,
        cfg: ControlFlowGraph,
        critical_nodes: dict[int, CriticalNode] | None = None,
    ) -> float:
        """
        Score an address for mutation safety.

        Higher scores indicate safer mutation sites.

        Args:
            address: Address to score
            cfg: Control flow graph
            critical_nodes: Pre-computed critical nodes (optional)

        Returns:
            Safety score from 0.0 (unsafe) to 1.0 (safe)
        """
        if critical_nodes is None:
            if self._detector is None or self._detector.cfg != cfg:
                self._detector = CriticalNodeDetector(cfg)
            critical_nodes = self._detector.find_all_critical_nodes()

        if address in critical_nodes:
            return 0.0

        for node in critical_nodes.values():
            if abs(address - node.address) <= node.exclusion_radius * 4:
                distance = max(1, abs(address - node.address))
                proximity_factor = node.exclusion_radius * 4 / distance
                return max(0.0, min(1.0, 1.0 - proximity_factor * 0.5))

        block = cfg.get_block(address)
        if block:
            if block.block_type == BlockType.CONDITIONAL:
                return 0.3

            if block.block_type == BlockType.CALL:
                return 0.4

            if len(block.predecessors) > 2:
                return 0.5

        return 0.8

    def get_safest_addresses(
        self,
        cfg: ControlFlowGraph,
        count: int = 10,
        critical_nodes: dict[int, CriticalNode] | None = None,
    ) -> list[tuple[int, float]]:
        """
        Get the safest addresses for mutation in a function.

        Args:
            cfg: Control flow graph
            count: Number of addresses to return
            critical_nodes: Pre-computed critical nodes (optional)

        Returns:
            List of (address, score) tuples sorted by score descending
        """
        if critical_nodes is None:
            detector = CriticalNodeDetector(cfg)
            critical_nodes = detector.find_all_critical_nodes()

        scores: list[tuple[int, float]] = []

        for addr, block in cfg.blocks.items():
            score = self.score_address(addr, cfg, critical_nodes)
            scores.append((addr, score))

        scores.sort(key=lambda x: x[1], reverse=True)

        return scores[:count]

    def get_all_scores(
        self,
        cfg: ControlFlowGraph,
        critical_nodes: dict[int, CriticalNode] | None = None,
    ) -> dict[int, float]:
        """
        Get safety scores for all addresses in the CFG.

        Args:
            cfg: Control flow graph
            critical_nodes: Pre-computed critical nodes (optional)

        Returns:
            Dictionary mapping addresses to safety scores
        """
        if critical_nodes is None:
            detector = CriticalNodeDetector(cfg)
            critical_nodes = detector.find_all_critical_nodes()

        scores: dict[int, float] = {}

        for addr in cfg.blocks:
            scores[addr] = self.score_address(addr, cfg, critical_nodes)

        return scores


def create_exclusion_zones(
    cfg: ControlFlowGraph,
    radius: int = 3,
) -> list[AddressRange]:
    """
    Convenience function to create exclusion zones.

    Args:
        cfg: Control flow graph
        radius: Exclusion radius

    Returns:
        List of AddressRange instances
    """
    detector = CriticalNodeDetector(cfg, default_exclusion_radius=radius)
    detector.find_all_critical_nodes()
    return detector.get_exclusion_zones()


def get_safe_mutation_addresses(
    cfg: ControlFlowGraph,
    count: int = 10,
) -> list[int]:
    """
    Convenience function to get safe mutation addresses.

    Args:
        cfg: Control flow graph
        count: Number of addresses to return

    Returns:
        List of safe addresses
    """
    scorer = MutationSafetyScorer()
    addresses = scorer.get_safest_addresses(cfg, count)
    return [addr for addr, _ in addresses]
