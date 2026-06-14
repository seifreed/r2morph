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

from r2morph.analysis.cfg import ControlFlowGraph
from r2morph.analysis.critical_nodes_detection import (
    build_critical_nodes,
    compute_exclusion_zones,
    compute_safe_regions,
    find_back_edges,
    find_branch_targets,
    find_call_sites,
    find_entry_exits,
    find_exception_handlers,
    find_loop_headers,
)
from r2morph.analysis.critical_nodes_models import AddressRange, CriticalNode
from r2morph.analysis.critical_nodes_scorer import get_all_scores, get_safest_addresses, score_address

logger = logging.getLogger(__name__)


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
        self._critical_nodes = build_critical_nodes(self.cfg, self.default_exclusion_radius)
        return self._critical_nodes

    def find_branch_targets(self) -> set[int]:
        """
        Find all branch targets in the CFG.

        Returns:
            Set of addresses that are targets of branch instructions
        """
        return find_branch_targets(self.cfg)

    def find_call_sites(self) -> set[int]:
        """
        Find all call instruction sites in the CFG.

        Returns:
            Set of addresses containing call instructions
        """
        return find_call_sites(self.cfg)

    def find_entry_exits(self) -> set[int]:
        """
        Find function entry and exit points.

        Returns:
            Set of entry and exit addresses
        """
        return find_entry_exits(self.cfg)

    def find_exception_handlers(self) -> set[int]:
        """
        Find exception handler addresses.

        Returns:
            Set of exception handler addresses
        """
        return find_exception_handlers(self.cfg)

    def find_loop_headers(self) -> set[int]:
        """
        Find loop header blocks.

        Returns:
            Set of loop header addresses
        """
        return find_loop_headers(self.cfg)

    def find_back_edges(self) -> list[tuple[int, int]]:
        """
        Find back edges in the CFG (edges that create loops).

        Returns:
            List of (from_addr, to_addr) tuples for back edges
        """
        return find_back_edges(self.cfg)

    def get_exclusion_zones(self) -> list[AddressRange]:
        """
        Get exclusion zones around critical nodes.

        Returns:
            List of AddressRange instances representing zones to avoid
        """
        if self._exclusion_zones:
            return self._exclusion_zones

        self._exclusion_zones = compute_exclusion_zones(self.cfg, self._critical_nodes)
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

        self._safe_regions = compute_safe_regions(self.cfg, self._exclusion_zones)
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

        return score_address(address, cfg, critical_nodes)

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

        return get_safest_addresses(cfg, count=count, critical_nodes=critical_nodes)

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

        return get_all_scores(cfg, critical_nodes)


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
