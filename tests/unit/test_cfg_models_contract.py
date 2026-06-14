from r2morph.analysis.cfg_models import (
    BasicBlock,
    BlockType,
    ControlFlowGraph,
    EdgeType,
    ExceptionEdge,
    TailCall,
)


def test_cfg_models_contract() -> None:
    block = BasicBlock(address=0x1000, size=0x20)
    block.add_successor(0x1010)
    block.add_predecessor(0x0FF0)
    assert block.is_conditional() is False
    assert block.get_terminal_instruction() is None

    cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
    cfg.add_block(block)
    cfg.add_edge(0x1000, 0x1010, EdgeType.NORMAL)
    cfg.add_exception_edge(ExceptionEdge(from_address=0x1000, to_address=0x2000, exception_type="seh"))
    cfg.add_tail_call(
        TailCall(
            source_address=0x1000,
            target_address=0x3000,
            source_function=0x1000,
            target_function=0x3000,
            target_name="callee",
        )
    )

    assert cfg.get_block(0x1000) is block
    assert cfg.entry_block is block
    assert cfg.blocks[0x1000].block_type == BlockType.NORMAL
    assert cfg.edges == [(0x1000, 0x1010)]
    assert cfg.exception_edges[0].exception_type == "seh"
    assert cfg.tail_calls[0].target_name == "callee"
    assert "digraph CFG" in cfg.to_dot()
