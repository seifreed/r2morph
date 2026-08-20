from pathlib import Path

from r2morph.analysis.cfg import BasicBlock, CFGBuilder, ControlFlowGraph
from r2morph.core.binary import Binary
from tests.utils.assertions import expect


def test_cfg_basic_operations():
    cfg = ControlFlowGraph(function_address=0x1000, function_name="test")

    block_a = BasicBlock(address=0x1000, size=4)
    block_b = BasicBlock(address=0x1004, size=4)
    block_c = BasicBlock(address=0x1008, size=4)

    cfg.add_block(block_a)
    cfg.add_block(block_b)
    cfg.add_block(block_c)

    cfg.add_edge(block_a.address, block_b.address)
    cfg.add_edge(block_b.address, block_c.address)
    cfg.add_edge(block_c.address, block_b.address)

    expect(not (cfg.get_block(block_a.address) is not block_a))
    expect(not (cfg.get_complexity() < 1))

    dominators = cfg.compute_dominators()
    expect(not (block_a.address not in dominators))

    loops = cfg.find_loops()
    expect(loops)

    dot = cfg.to_dot()
    expect(not ("digraph CFG" not in dot))


def test_cfg_builder_with_real_binary():
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        expect(functions)

        func = functions[0]
        builder = CFGBuilder(bin_obj)
        cfg = builder.build_cfg(func.get("offset", 0), func.get("name", "func"))
        expect(cfg.function_address == func.get("offset", 0))
        expect(cfg.function_name)

        all_cfgs = builder.build_all_cfgs()
        expect(isinstance(all_cfgs, dict))
