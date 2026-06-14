"""Pure mutation-safety scoring helpers."""

from __future__ import annotations

from r2morph.analysis.cfg import BlockType, ControlFlowGraph
from r2morph.analysis.critical_nodes_models import CriticalNode


def score_address(
    address: int,
    cfg: ControlFlowGraph,
    critical_nodes: dict[int, CriticalNode],
) -> float:
    """Score an address for mutation safety."""
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
    cfg: ControlFlowGraph,
    *,
    count: int,
    critical_nodes: dict[int, CriticalNode],
) -> list[tuple[int, float]]:
    """Return the safest addresses for mutation in a function."""
    scores: list[tuple[int, float]] = []
    for addr in cfg.blocks:
        scores.append((addr, score_address(addr, cfg, critical_nodes)))

    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:count]


def get_all_scores(
    cfg: ControlFlowGraph,
    critical_nodes: dict[int, CriticalNode],
) -> dict[int, float]:
    """Return safety scores for all addresses in the CFG."""
    return {addr: score_address(addr, cfg, critical_nodes) for addr in cfg.blocks}
