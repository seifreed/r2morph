"""
Control Flow Graph (CFG) data models for binary functions.

Provides graph-based representations of program control flow.
Includes support for:
- Basic blocks and edges
- Exception handling metadata
- Tail call metadata
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EdgeType(Enum):
    """Type of CFG edge."""

    NORMAL = "normal"
    CONDITIONAL_TRUE = "conditional_true"
    CONDITIONAL_FALSE = "conditional_false"
    CALL = "call"
    RETURN = "return"
    TAIL_CALL = "tail_call"
    EXCEPTION = "exception"
    INDIRECT = "indirect"
    SWITCH = "switch"


class BlockType(Enum):
    """Type of basic block."""

    NORMAL = "normal"
    CONDITIONAL = "conditional"
    RETURN = "return"
    CALL = "call"
    ENTRY = "entry"
    EXIT = "exit"
    EXCEPTION_HANDLER = "exception_handler"
    LANDING_PAD = "landing_pad"
    PLT_STUB = "plt_stub"


class BasicBlock:
    """
    Represents a basic block in the control flow graph.

    A basic block is a sequence of instructions with:
    - Single entry point (first instruction)
    - Single exit point (last instruction)
    - No branches except at the end
    """

    def __init__(
        self,
        address: int,
        size: int,
        instructions: list[dict[str, Any]] | None = None,
        successors: list[int] | None = None,
        predecessors: list[int] | None = None,
        block_type: BlockType = BlockType.NORMAL,
    ):
        self.address = address
        self.size = size
        self.instructions = instructions if instructions is not None else []
        self.successors = successors if successors is not None else []
        self.predecessors = predecessors if predecessors is not None else []
        self.block_type = block_type
        self.edge_types: dict[int, EdgeType] = {}
        self.metadata: dict[str, Any] = {}

    def __repr__(self) -> str:
        return f"<BasicBlock @ 0x{self.address:x} size={self.size} type={self.block_type.value}>"

    def add_successor(self, address: int, edge_type: EdgeType = EdgeType.NORMAL) -> None:
        """Add a successor block with optional edge type."""
        if address not in self.successors:
            self.successors.append(address)
            self.edge_types[address] = edge_type

    def add_predecessor(self, address: int) -> None:
        """Add a predecessor block."""
        if address not in self.predecessors:
            self.predecessors.append(address)

    def is_conditional(self) -> bool:
        """Check if this is a conditional branch block."""
        return self.block_type == BlockType.CONDITIONAL or len(self.successors) > 1

    def is_return(self) -> bool:
        """Check if this block ends with a return."""
        return self.block_type == BlockType.RETURN or len(self.successors) == 0

    def is_tail_call_source(self) -> bool:
        """Check if this block contains a tail call."""
        return EdgeType.TAIL_CALL in self.edge_types.values()

    def get_terminal_instruction(self) -> dict[str, Any] | None:
        """Get the last instruction in the block."""
        if self.instructions:
            return self.instructions[-1]
        return None

    def get_jump_targets(self) -> list[int]:
        """Get all jump targets from this block."""
        targets = []
        for insn in self.instructions:
            mnemonic = insn.get("type", "").lower()
            if mnemonic in ("jmp", "cjmp", "call", "ujmp"):
                jump_addr = insn.get("jump")
                if jump_addr and isinstance(jump_addr, int):
                    targets.append(jump_addr)
        return targets


@dataclass
class ExceptionEdge:
    """Represents an exception handling edge in the CFG."""

    from_address: int
    to_address: int
    exception_type: str
    landing_pad: int | None = None
    action: str = "catch"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TailCall:
    """Represents a detected tail call."""

    source_address: int
    target_address: int
    source_function: int
    target_function: int | None = None
    target_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ControlFlowGraph:
    """
    Control Flow Graph for a function.

    Represents the control flow structure as a directed graph of basic blocks.
    """

    function_address: int
    function_name: str
    entry_block: BasicBlock | None = None
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    edges: list[tuple[int, int]] = field(default_factory=list)
    exception_edges: list[ExceptionEdge] = field(default_factory=list)
    tail_calls: list[TailCall] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_block(self, block: BasicBlock) -> None:
        """Add a basic block to the CFG."""
        self.blocks[block.address] = block
        if self.entry_block is None:
            self.entry_block = block

    def add_edge(self, from_addr: int, to_addr: int, edge_type: EdgeType = EdgeType.NORMAL) -> None:
        """Add a control flow edge."""
        edge = (from_addr, to_addr)
        if edge not in self.edges:
            self.edges.append(edge)

        if from_addr in self.blocks:
            self.blocks[from_addr].add_successor(to_addr, edge_type)
        if to_addr in self.blocks:
            self.blocks[to_addr].add_predecessor(from_addr)

    def add_exception_edge(self, edge: ExceptionEdge) -> None:
        """Add an exception handling edge."""
        self.exception_edges.append(edge)

    def add_tail_call(self, tail_call: TailCall) -> None:
        """Add a detected tail call."""
        self.tail_calls.append(tail_call)

    def get_block(self, address: int) -> BasicBlock | None:
        """Get a basic block by address."""
        return self.blocks.get(address)

    def get_successors(self, address: int) -> list[BasicBlock]:
        """Get successor blocks of a given block."""
        block = self.blocks.get(address)
        if not block:
            return []
        return [self.blocks[addr] for addr in block.successors if addr in self.blocks]

    def get_predecessors(self, address: int) -> list[BasicBlock]:
        """Get predecessor blocks of a given block."""
        block = self.blocks.get(address)
        if not block:
            return []
        return [self.blocks[addr] for addr in block.predecessors if addr in self.blocks]

    def compute_dominators(self) -> dict[int, set[int]]:
        """
        Compute dominator tree using iterative algorithm.

        A block X dominates block Y if all paths from entry to Y go through X.

        Returns:
            Dictionary mapping block address to set of dominator addresses
        """
        if not self.entry_block:
            return {}

        dominators: dict[int, set[int]] = {}

        all_blocks = set(self.blocks.keys())
        dominators[self.entry_block.address] = {self.entry_block.address}

        for addr in self.blocks:
            if addr != self.entry_block.address:
                dominators[addr] = all_blocks.copy()

        changed = True
        max_iterations = len(self.blocks) * len(self.blocks) + 1
        iterations = 0
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            for addr in self.blocks:
                if addr == self.entry_block.address:
                    continue

                preds = self.get_predecessors(addr)
                if preds:
                    new_dom = set.intersection(*[dominators[p.address] for p in preds])
                    new_dom.add(addr)

                    if new_dom != dominators[addr]:
                        dominators[addr] = new_dom
                        changed = True
                elif dominators[addr] != all_blocks:
                    dominators[addr] = all_blocks.copy()
                    changed = True

        return dominators

    def find_loops(self) -> list[tuple[int, int]]:
        """
        Find loops in the CFG using back edges.

        A back edge is an edge from a block to one of its dominators.

        Returns:
            List of (from_addr, to_addr) tuples representing loop back edges
        """
        dominators = self.compute_dominators()
        loops = []

        for from_addr, to_addr in self.edges:
            if to_addr in dominators.get(from_addr, set()):
                loops.append((from_addr, to_addr))

        return loops

    def get_complexity(self) -> int:
        """
        Calculate cyclomatic complexity.

        Cyclomatic complexity = E - N + 2P
        where E = edges, N = nodes, P = connected components (1 for a single function)

        Returns:
            Cyclomatic complexity value
        """
        e = len(self.edges)
        n = len(self.blocks)
        p = 1

        complexity = e - n + 2 * p
        return max(1, complexity)

    def to_dot(self) -> str:
        """
        Generate GraphViz DOT representation of the CFG.

        Returns:
            DOT format string for visualization
        """
        lines = [
            "digraph CFG {",
            "  node [shape=box, style=rounded];",
            f'  label="{self.function_name} @ 0x{self.function_address:x}";',
            "",
        ]

        for addr, block in self.blocks.items():
            label = f"0x{addr:x}\\n{len(block.instructions)} instructions"
            color = "lightblue" if block == self.entry_block else "white"
            shape = "box" if block.block_type == BlockType.NORMAL else "diamond"

            lines.append(f'  "0x{addr:x}" [label="{label}", fillcolor={color}, style="filled,rounded", shape={shape}];')

        for from_addr, to_addr in self.edges:
            lines.append(f'  "0x{from_addr:x}" -> "0x{to_addr:x}";')

        lines.append("}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"<CFG {self.function_name} @ 0x{self.function_address:x} "
            f"blocks={len(self.blocks)} edges={len(self.edges)} "
            f"complexity={self.get_complexity()}>"
        )


__all__ = [
    "BasicBlock",
    "BlockType",
    "ControlFlowGraph",
    "EdgeType",
    "ExceptionEdge",
    "TailCall",
]
