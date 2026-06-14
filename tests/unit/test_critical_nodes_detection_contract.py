from r2morph.analysis.cfg import BasicBlock, BlockType, ControlFlowGraph
from r2morph.analysis.critical_nodes_detection import (
    build_critical_nodes,
    compute_exclusion_zones,
    compute_safe_regions,
    find_back_edges,
    find_branch_targets,
    find_call_sites,
    find_entry_exits,
)


def _build_cfg() -> ControlFlowGraph:
    cfg = ControlFlowGraph(function_address=0x1000, function_name="demo")
    entry = BasicBlock(
        address=0x1000,
        size=8,
        instructions=[
            {"offset": 0x1000, "type": "call", "disasm": "call 0x2000"},
            {"offset": 0x1005, "type": "jmp", "disasm": "jmp 0x1010", "jump": 0x1010},
        ],
        successors=[0x1010],
        predecessors=[],
        block_type=BlockType.ENTRY,
    )
    exit_block = BasicBlock(
        address=0x1010,
        size=4,
        instructions=[{"offset": 0x1010, "type": "ret", "disasm": "ret"}],
        successors=[],
        predecessors=[0x1000],
        block_type=BlockType.RETURN,
    )
    cfg.add_block(entry)
    cfg.add_block(exit_block)
    cfg.add_edge(0x1000, 0x1010)
    return cfg


def test_critical_nodes_detection_contract() -> None:
    cfg = _build_cfg()

    assert find_branch_targets(cfg) == {0x1010}
    assert find_call_sites(cfg) == {0x1000}
    assert find_entry_exits(cfg) == {0x1000, 0x1010}
    assert find_back_edges(cfg) == []

    critical_nodes = build_critical_nodes(cfg, default_exclusion_radius=3)
    zones = compute_exclusion_zones(cfg, critical_nodes)
    safe_regions = compute_safe_regions(cfg, zones)

    assert 0x1000 in critical_nodes
    assert zones
    assert safe_regions == []
