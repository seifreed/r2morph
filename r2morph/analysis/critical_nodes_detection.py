"""Pure critical-node detection helpers."""

from __future__ import annotations

from r2morph.analysis.cfg import BlockType, ControlFlowGraph
from r2morph.analysis.critical_nodes_models import AddressRange, CriticalNode


def find_branch_targets(cfg: ControlFlowGraph) -> set[int]:
    targets: set[int] = set()

    for _, to_addr in cfg.edges:
        targets.add(to_addr)

    for _, block in cfg.blocks.items():
        for insn in block.instructions:
            jump_target = insn.get("jump")
            if jump_target and isinstance(jump_target, int):
                targets.add(jump_target)

    return targets


def find_call_sites(cfg: ControlFlowGraph) -> set[int]:
    call_sites: set[int] = set()

    for addr, block in cfg.blocks.items():
        for insn in block.instructions:
            insn_type = insn.get("type", "").lower()
            if insn_type == "call":
                call_sites.add(insn.get("offset", addr))

            disasm = insn.get("disasm", "").lower()
            if disasm.startswith("call"):
                call_sites.add(insn.get("offset", addr))

    return call_sites


def find_entry_exits(cfg: ControlFlowGraph) -> set[int]:
    entry_exits: set[int] = set()

    if cfg.entry_block:
        entry_exits.add(cfg.entry_block.address)

    for addr, block in cfg.blocks.items():
        if block.block_type == BlockType.RETURN:
            entry_exits.add(addr)

        if len(block.successors) == 0 and block.block_type != BlockType.RETURN:
            entry_exits.add(addr)

    return entry_exits


def find_exception_handlers(cfg: ControlFlowGraph) -> set[int]:
    handlers: set[int] = set()

    for edge in cfg.exception_edges:
        if edge.to_address:
            handlers.add(edge.to_address)

    for addr, block in cfg.blocks.items():
        if block.block_type == BlockType.EXCEPTION_HANDLER:
            handlers.add(addr)
        if block.block_type == BlockType.LANDING_PAD:
            handlers.add(addr)
        if block.metadata.get("is_landing_pad"):
            handlers.add(addr)

    return handlers


def find_loop_headers(cfg: ControlFlowGraph) -> set[int]:
    loop_headers: set[int] = set()

    for _, to_addr in cfg.find_loops():
        loop_headers.add(to_addr)

    dominators = cfg.compute_dominators()
    for from_addr, to_addr in cfg.edges:
        if to_addr in dominators.get(from_addr, set()):
            loop_headers.add(to_addr)

    return loop_headers


def find_back_edges(cfg: ControlFlowGraph) -> list[tuple[int, int]]:
    return cfg.find_loops()


def build_critical_nodes(cfg: ControlFlowGraph, default_exclusion_radius: int) -> dict[int, CriticalNode]:
    critical_nodes: dict[int, CriticalNode] = {}

    for addr in find_branch_targets(cfg):
        critical_nodes[addr] = CriticalNode(
            address=addr,
            node_type="branch_target",
            reason="Target of a branch instruction",
            exclusion_radius=default_exclusion_radius,
        )

    for addr in find_call_sites(cfg):
        critical_nodes[addr] = CriticalNode(
            address=addr,
            node_type="call_site",
            reason="Call instruction site",
            exclusion_radius=default_exclusion_radius,
        )

    for addr in find_entry_exits(cfg):
        critical_nodes[addr] = CriticalNode(
            address=addr,
            node_type="entry_exit",
            reason="Function entry or exit point",
            exclusion_radius=default_exclusion_radius + 2,
        )

    for addr in find_exception_handlers(cfg):
        critical_nodes[addr] = CriticalNode(
            address=addr,
            node_type="exception_handler",
            reason="Exception handling code",
            exclusion_radius=default_exclusion_radius + 1,
        )

    for addr in find_loop_headers(cfg):
        critical_nodes[addr] = CriticalNode(
            address=addr,
            node_type="loop_header",
            reason="Loop header block",
            exclusion_radius=default_exclusion_radius,
        )

    for from_addr, _ in find_back_edges(cfg):
        if from_addr not in critical_nodes:
            critical_nodes[from_addr] = CriticalNode(
                address=from_addr,
                node_type="back_edge",
                reason="Source of loop back edge",
                exclusion_radius=default_exclusion_radius,
            )

    return critical_nodes


def compute_exclusion_zones(
    cfg: ControlFlowGraph,
    critical_nodes: dict[int, CriticalNode],
) -> list[AddressRange]:
    ranges: list[AddressRange] = []

    for addr, node in critical_nodes.items():
        radius = node.exclusion_radius
        start = addr - (radius * 4)
        end = addr + (radius * 4)

        block = cfg.get_block(addr)
        if block:
            start = max(start, block.address)
            end = min(end, block.address + block.size - 1)

        ranges.append(AddressRange(start=start, end=end))

    ranges.sort(key=lambda r: r.start)

    merged: list[AddressRange] = []
    for zone in ranges:
        if merged and merged[-1].overlaps(zone):
            merged[-1] = merged[-1].merge(zone)
        else:
            merged.append(zone)

    return merged


def compute_safe_regions(
    cfg: ControlFlowGraph,
    exclusion_zones: list[AddressRange],
) -> list[AddressRange]:
    all_blocks = sorted([(addr, block) for addr, block in cfg.blocks.items()], key=lambda x: x[0])

    safe: list[AddressRange] = []
    for addr, block in all_blocks:
        block_start = addr
        block_end = addr + block.size - 1

        if any(zone.overlaps(AddressRange(start=block_start, end=block_end)) for zone in exclusion_zones):
            continue

        safe.append(AddressRange(start=block_start, end=block_end))

    return safe

