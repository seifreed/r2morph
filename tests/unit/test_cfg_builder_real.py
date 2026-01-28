from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph, CFGBuilder


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

    assert cfg.get_block(block_a.address) is block_a
    assert cfg.get_complexity() >= 1

    dominators = cfg.compute_dominators()
    assert block_a.address in dominators

    loops = cfg.find_loops()
    assert loops

    dot = cfg.to_dot()
    assert "digraph CFG" in dot


def test_cfg_builder_with_real_binary():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        assert functions

        func = functions[0]
        builder = CFGBuilder(bin_obj)
        cfg = builder.build_cfg(func.get("offset", 0), func.get("name", "func"))
        assert cfg.function_address == func.get("offset", 0)
        assert cfg.function_name

        all_cfgs = builder.build_all_cfgs()
        assert isinstance(all_cfgs, dict)
