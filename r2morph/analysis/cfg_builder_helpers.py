"""Helpers for CFGBuilder construction and edge classification."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.analysis.cfg_models import BasicBlock, BlockType, ControlFlowGraph, EdgeType
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def classify_block_type(r2_block: dict[str, Any]) -> BlockType:
    """Map a radare2 block record to a block type."""
    if r2_block.get("fail"):
        return BlockType.CONDITIONAL
    if r2_block.get("type") == "call":
        return BlockType.CALL
    return BlockType.NORMAL


def collect_block_instructions(binary: Binary, function_address: int, addr: int, size: int) -> list[dict[str, Any]]:
    """Return instructions that fall inside a basic block range."""
    try:
        all_instrs = binary.get_function_disasm(function_address)
    except (ValueError, OSError, BrokenPipeError, RuntimeError) as exc:
        logger.debug(f"Could not get instructions for block at 0x{addr:x}: {exc}")
        return []

    return [insn for insn in all_instrs if addr <= insn.get("offset", 0) < addr + size]


def classify_edge_type(block: BasicBlock | None, terminal_mnemonic: str, *, is_fail_edge: bool = False) -> EdgeType:
    """Classify a CFG edge based on the terminal instruction of its source block."""
    mnemonic = terminal_mnemonic.lower()
    if is_fail_edge and mnemonic == "cjmp":
        return EdgeType.CONDITIONAL_FALSE
    if mnemonic == "ujmp":
        return EdgeType.INDIRECT
    if mnemonic == "cjmp":
        return EdgeType.CONDITIONAL_TRUE if not is_fail_edge else EdgeType.CONDITIONAL_FALSE
    if mnemonic in ("jmp", "call"):
        return EdgeType.NORMAL
    return EdgeType.NORMAL


def populate_cfg_blocks(cfg: ControlFlowGraph, binary: Binary, function_address: int, r2_blocks: list[dict[str, Any]]) -> None:
    """Build CFG blocks from radare2 block metadata."""
    for r2_block in r2_blocks:
        addr = r2_block.get("addr", 0)
        size = r2_block.get("size", 0)
        block = BasicBlock(
            address=addr,
            size=size,
            instructions=collect_block_instructions(binary, function_address, addr, size),
            successors=[],
            predecessors=[],
            block_type=classify_block_type(r2_block),
        )
        cfg.add_block(block)


def populate_cfg_edges(cfg: ControlFlowGraph, r2_blocks: list[dict[str, Any]]) -> None:
    """Build CFG edges from radare2 jump/fail metadata."""
    for r2_block in r2_blocks:
        from_addr = r2_block.get("addr", 0)
        src_block = cfg.get_block(from_addr)
        terminal = src_block.get_terminal_instruction() if src_block else None
        mnemonic = terminal.get("type", "") if terminal else ""

        if r2_block.get("jump"):
            cfg.add_edge(from_addr, r2_block["jump"], classify_edge_type(src_block, mnemonic))

        if r2_block.get("fail"):
            cfg.add_edge(from_addr, r2_block["fail"], classify_edge_type(src_block, mnemonic, is_fail_edge=True))


__all__ = [
    "classify_block_type",
    "classify_edge_type",
    "collect_block_instructions",
    "populate_cfg_blocks",
    "populate_cfg_edges",
]
