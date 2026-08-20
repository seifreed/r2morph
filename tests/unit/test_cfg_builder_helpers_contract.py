from types import SimpleNamespace

from r2morph.analysis.cfg import CFGBuilder
from r2morph.analysis.cfg_builder_helpers import (
    classify_block_type,
    classify_edge_type,
    collect_block_instructions,
    populate_cfg_blocks,
    populate_cfg_edges,
)
from r2morph.analysis.cfg_models import BasicBlock, BlockType, ControlFlowGraph, EdgeType
from tests.utils.assertions import expect

_EXPECTED_BINARY_DISASM_CALLS_2 = 2
_EXPECTED_CFG_FUNCTION_ADDRESS_4096 = 0x1000


class _Binary:
    def __init__(self) -> None:
        self.disasm_calls = 0

    def get_function_disasm(self, function_address: int):
        self.disasm_calls += 1
        return [
            {"offset": 0x1000, "type": "mov"},
            {"offset": 0x1004, "type": "cjmp", "jump": 0x2000},
            {"offset": 0x1008, "type": "jmp", "jump": 0x3000},
        ]


def test_cfg_builder_helpers_contract() -> None:
    binary = _Binary()
    cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
    r2_blocks = [
        {"addr": 0x1000, "size": 0x10, "fail": 0x1008},
        {"addr": 0x1010, "size": 0x10, "type": "call", "jump": 0x4000},
    ]

    populate_cfg_blocks(cfg, binary, 0x1000, r2_blocks)
    populate_cfg_edges(cfg, r2_blocks)

    expect(binary.disasm_calls == _EXPECTED_BINARY_DISASM_CALLS_2)
    expect(cfg.get_block(4096).block_type == BlockType.CONDITIONAL)
    expect(cfg.get_block(4112).block_type == BlockType.CALL)
    expect(not ((0x1000, 0x1008) not in cfg.edges))
    expect(not ((0x1010, 0x4000) not in cfg.edges))

    expect(classify_block_type({"fail": 1}) == BlockType.CONDITIONAL)
    expect(classify_block_type({"type": "call"}) == BlockType.CALL)
    expect(classify_block_type({}) == BlockType.NORMAL)

    block = BasicBlock(address=0x2000, size=8, instructions=[{"type": "cjmp"}])
    expect(classify_edge_type(block, "cjmp") == EdgeType.CONDITIONAL_TRUE)
    expect(classify_edge_type(block, "cjmp", is_fail_edge=True) == EdgeType.CONDITIONAL_FALSE)
    expect(classify_edge_type(block, "ujmp") == EdgeType.INDIRECT)
    expect(classify_edge_type(block, "jmp") == EdgeType.NORMAL)

    expect(collect_block_instructions(binary, 0x1000, 0x1000, 0x10))


def test_cfg_builder_still_builds_cfgs_with_helpers() -> None:
    binary = SimpleNamespace(
        is_analyzed=lambda: True,
        get_basic_blocks=lambda _addr: [{"addr": 0x1000, "size": 0x10}],
        get_function_disasm=lambda _addr: [{"offset": 0x1000, "type": "ret"}],
        get_functions=lambda: [{"offset": 0x1000, "name": "main"}],
        get_arch_info=lambda: {"format": "ELF"},
        r2=None,
    )
    cfg = CFGBuilder(binary).build_cfg(0x1000, "main")
    expect(cfg.function_address == _EXPECTED_CFG_FUNCTION_ADDRESS_4096)
    expect(cfg.get_block(0x1000) is not None)
