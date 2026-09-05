"""Regression tests for virtualization preflight dataflow coverage."""

from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph
from r2morph.mutations.code_virtualization_apply import _static_dataflow_is_complete
from tests.utils.assertions import expect


def _branching_cfg() -> ControlFlowGraph:
    cfg = ControlFlowGraph(function_address=0x1000, function_name="branch")
    cfg.add_block(
        BasicBlock(
            address=0x1000,
            size=5,
            instructions=[{"offset": 0x1000, "disasm": "mov rax, 1", "type": "mov"}],
        )
    )
    cfg.add_block(
        BasicBlock(
            address=0x1010,
            size=5,
            instructions=[{"offset": 0x1010, "disasm": "add rax, 2", "type": "add"}],
        )
    )
    cfg.add_block(
        BasicBlock(
            address=0x1020,
            size=5,
            instructions=[{"offset": 0x1020, "disasm": "sub rax, 2", "type": "sub"}],
        )
    )
    cfg.add_block(
        BasicBlock(
            address=0x1030,
            size=1,
            instructions=[{"offset": 0x1030, "disasm": "ret", "type": "ret"}],
        )
    )
    cfg.add_edge(0x1000, 0x1010)
    cfg.add_edge(0x1000, 0x1020)
    cfg.add_edge(0x1010, 0x1030)
    cfg.add_edge(0x1020, 0x1030)
    return cfg


def test_static_dataflow_branching_cfg_proves_ssa_and_liveness_coverage() -> None:
    expect(_static_dataflow_is_complete(_branching_cfg()))
