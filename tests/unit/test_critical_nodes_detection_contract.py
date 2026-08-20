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
from tests.utils.assertions import expect

_EXPECTED_CRITICAL_NODES_4096 = 0x1000


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

    expect(find_branch_targets(cfg) == {4112})
    expect(find_call_sites(cfg) == {4096})
    expect(find_entry_exits(cfg) == {4096, 4112})
    expect(find_back_edges(cfg) == [])

    critical_nodes = build_critical_nodes(cfg, default_exclusion_radius=3)
    zones = compute_exclusion_zones(cfg, critical_nodes)
    safe_regions = compute_safe_regions(cfg, zones)

    expect(not (_EXPECTED_CRITICAL_NODES_4096 not in critical_nodes))
    expect(zones)
    expect(safe_regions == [])
