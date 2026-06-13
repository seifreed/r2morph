from types import SimpleNamespace

from r2morph.analysis.cfg import BasicBlock, BlockType, ControlFlowGraph
from r2morph.validation.constraint_cache import ConstraintCache, ConstraintCacheEntry
from r2morph.validation.state_merging import ImprovedStateMerging


def test_constraint_cache_round_trip_and_statistics() -> None:
    cache = ConstraintCache(max_size=4, ttl_seconds=3600)
    constraint = SimpleNamespace(name="x == 1")
    result = SimpleNamespace(addr=0x1000)

    cache.set(constraint, result, is_satisfiable=True)

    entry = cache.get(constraint)

    assert isinstance(entry, ConstraintCacheEntry)
    assert entry.is_satisfiable is True
    assert entry.result is result
    assert cache.get_statistics()["entries"] == 1


def test_improved_state_merging_finds_join_block() -> None:
    merger = ImprovedStateMerging()
    cfg = ControlFlowGraph(function_address=0x1000, function_name="test")

    entry = BasicBlock(
        address=0x1000,
        size=8,
        instructions=[],
        successors=[0x1010, 0x1020],
        predecessors=[],
        block_type=BlockType.ENTRY,
    )
    left = BasicBlock(
        address=0x1010,
        size=4,
        instructions=[],
        successors=[0x1030],
        predecessors=[0x1000],
        block_type=BlockType.NORMAL,
    )
    right = BasicBlock(
        address=0x1020,
        size=4,
        instructions=[],
        successors=[0x1030],
        predecessors=[0x1000],
        block_type=BlockType.NORMAL,
    )
    merge = BasicBlock(
        address=0x1030,
        size=4,
        instructions=[],
        successors=[],
        predecessors=[0x1010, 0x1020],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(entry)
    cfg.add_block(left)
    cfg.add_block(right)
    cfg.add_block(merge)
    cfg.add_edge(0x1000, 0x1010)
    cfg.add_edge(0x1000, 0x1020)
    cfg.add_edge(0x1010, 0x1030)
    cfg.add_edge(0x1020, 0x1030)

    assert 0x1030 in merger.find_merge_points(cfg)
