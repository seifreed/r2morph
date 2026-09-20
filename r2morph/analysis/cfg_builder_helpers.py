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


def populate_cfg_blocks(
    cfg: ControlFlowGraph, binary: Binary, function_address: int, r2_blocks: list[dict[str, Any]]
) -> None:
    """Build CFG blocks from radare2 block metadata."""
    try:
        function_instructions = binary.get_function_disasm(function_address)
    except (ValueError, OSError, BrokenPipeError, RuntimeError) as exc:
        logger.debug(f"Could not get instructions for function at 0x{function_address:x}: {exc}")
        function_instructions = []
    for r2_block in r2_blocks:
        addr = r2_block.get("addr", 0)
        size = r2_block.get("size", 0)
        block_instructions = [
            instruction for instruction in function_instructions if addr <= instruction.get("offset", 0) < addr + size
        ]
        if not block_instructions:
            block_instructions = _read_block_instructions(binary, addr, size)
        block = BasicBlock(
            address=addr,
            size=size,
            instructions=block_instructions,
            successors=[],
            predecessors=[],
            block_type=classify_block_type(r2_block),
        )
        cfg.add_block(block)


def _read_block_instructions(binary: Binary, address: int, size: int) -> list[dict[str, Any]]:
    """Recover a block omitted by radare2's whole-function disassembly."""
    if size <= 0 or getattr(binary, "r2", None) is None:
        return []
    for command in ("pdbj", "pdj"):
        try:
            instructions = binary.r2.cmdj(f"{command} {size} @ {address}") or []
        except (AttributeError, OSError, BrokenPipeError, RuntimeError, TypeError, ValueError) as exc:
            logger.debug("Could not recover block at 0x%x with %s: %s", address, command, exc)
            continue
        if not isinstance(instructions, list):
            continue
        recovered: list[dict[str, Any]] = []
        for instruction in instructions:
            if not isinstance(instruction, dict):
                continue
            offset = instruction.get("offset", instruction.get("addr"))
            if not isinstance(offset, int) or not address <= offset < address + size:
                continue
            recovered.append(instruction if "offset" in instruction else {**instruction, "offset": offset})
        if recovered:
            return recovered
    return []


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
