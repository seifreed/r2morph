from r2morph.analysis.cfg_models import (
    BasicBlock,
    BlockType,
    ControlFlowGraph,
    EdgeType,
    ExceptionEdge,
    TailCall,
)
from tests.utils.assertions import expect


def test_cfg_models_contract() -> None:
    block = BasicBlock(address=0x1000, size=0x20)
    block.add_successor(0x1010)
    block.add_predecessor(0x0FF0)
    expect(not (block.is_conditional() is not False))
    expect(not (block.get_terminal_instruction() is not None))

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

    expect(not (cfg.get_block(0x1000) is not block))
    expect(not (cfg.entry_block is not block))
    expect(cfg.blocks[4096].block_type == BlockType.NORMAL)
    expect(cfg.edges == [(4096, 4112)])
    expect(cfg.exception_edges[0].exception_type == "seh")
    expect(cfg.tail_calls[0].target_name == "callee")
    expect(not ("digraph CFG" not in cfg.to_dot()))
