from r2morph.analysis.cfg import BasicBlock, BlockType, ControlFlowGraph
from r2morph.analysis.dataflow_models import DataFlowResult, Definition, Register
from r2morph.analysis.dataflow_queries import find_block_containing_address, is_address_calculation, is_safe_to_mutate
from tests.utils.assertions import expect

_EXPECTED_FIND_BLOCK_CONTAINING_ADDRESS_CFG_0X1000_4096 = 0x1000


def test_dataflow_queries_contract() -> None:
    cfg = ControlFlowGraph(function_address=0x1000, function_name="demo")
    cfg.add_block(
        BasicBlock(
            address=0x1000,
            size=0x10,
            instructions=[{"offset": 0x1000, "type": "lea", "disasm": "lea rax, [rbp-8]"}],
            successors=[],
            predecessors=[],
            block_type=BlockType.NORMAL,
        )
    )
    result = DataFlowResult()
    result.live_in[0x1000] = {Register("rbp", 64)}
    result.reaching_in[0x1000] = {
        Definition(address=0x1000, register=Register("rax", 64), instruction="lea rax, [rbp-8]")
    }

    expect(find_block_containing_address(cfg, 4096) == _EXPECTED_FIND_BLOCK_CONTAINING_ADDRESS_CFG_0X1000_4096)
    expect(is_address_calculation(next(iter(result.reaching_in[0x1000]))))
    expect(not (is_safe_to_mutate(cfg, result, 0x1000, "instruction_expansion")[0] is not False))
