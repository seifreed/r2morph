"""
Control Flow Graph (CFG) analysis for binary functions.

Provides graph-based representations of program control flow.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, List, Tuple

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


@dataclass
class BasicBlock:
    """
    Represents a basic block in the control flow graph.

    A basic block is a sequence of instructions with:
    - Single entry point (first instruction)
    - Single exit point (last instruction)
    - No branches except at the end
    """

    address: int
    size: int
    instructions: list[dict[str, Any]] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    type: str = "normal"

    def __repr__(self) -> str:
        return f"<BasicBlock @ 0x{self.address:x} size={self.size} type={self.type}>"

    def add_successor(self, address: int):
        """Add a successor block."""
        if address not in self.successors:
            self.successors.append(address)

    def add_predecessor(self, address: int):
        """Add a predecessor block."""
        if address not in self.predecessors:
            self.predecessors.append(address)

    def is_conditional(self) -> bool:
        """Check if this is a conditional branch block."""
        return self.type == "conditional" or len(self.successors) > 1

    def is_return(self) -> bool:
        """Check if this block ends with a return."""
        return self.type == "return" or len(self.successors) == 0


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
    edges: list[Tuple[int, int]] = field(default_factory=list)

    def add_block(self, block: BasicBlock):
        """Add a basic block to the CFG."""
        self.blocks[block.address] = block
        if self.entry_block is None:
            self.entry_block = block

    def add_edge(self, from_addr: int, to_addr: int):
        """Add a control flow edge."""
        edge = (from_addr, to_addr)
        if edge not in self.edges:
            self.edges.append(edge)

        if from_addr in self.blocks:
            self.blocks[from_addr].add_successor(to_addr)
        if to_addr in self.blocks:
            self.blocks[to_addr].add_predecessor(from_addr)

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
        while changed:
            changed = False
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
                logger.debug(f"Found loop: 0x{from_addr:x} -> 0x{to_addr:x}")

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
            shape = "box" if block.type == "normal" else "diamond"

            lines.append(
                f'  "0x{addr:x}" [label="{label}", fillcolor={color}, '
                f'style="filled,rounded", shape={shape}];'
            )

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


class CFGBuilder:
    """
    Builder for constructing Control Flow Graphs from binary functions.
    """

    def __init__(self, binary: Binary):
        """
        Initialize CFG builder.

        Args:
            binary: Binary instance
        """
        self.binary = binary

    def build_cfg(self, function_address: int, function_name: str = "") -> ControlFlowGraph:
        """
        Build a CFG for a function.

        Args:
            function_address: Address of the function
            function_name: Name of the function (optional)

        Returns:
            ControlFlowGraph instance
        """
        cfg = ControlFlowGraph(
            function_address=function_address,
            function_name=function_name or f"func_{function_address:x}",
        )

        try:
            r2_blocks = self.binary.get_basic_blocks(function_address)
        except Exception as e:
            logger.error(f"Failed to get basic blocks for function @ 0x{function_address:x}: {e}")
            return cfg

        for r2_block in r2_blocks:
            addr = r2_block.get("addr", 0)
            size = r2_block.get("size", 0)

            block_type = "normal"
            if r2_block.get("fail"):
                block_type = "conditional"
            elif r2_block.get("type") == "call":
                block_type = "call"

            instructions = []
            try:
                all_instrs = self.binary.get_function_disasm(function_address)
                instructions = [
                    insn for insn in all_instrs if addr <= insn.get("offset", 0) < addr + size
                ]
            except Exception:
                pass

            block = BasicBlock(
                address=addr,
                size=size,
                instructions=instructions,
                type=block_type,
            )

            cfg.add_block(block)

        for r2_block in r2_blocks:
            from_addr = r2_block.get("addr", 0)

            if r2_block.get("jump"):
                to_addr = r2_block["jump"]
                cfg.add_edge(from_addr, to_addr)

            if r2_block.get("fail"):
                to_addr = r2_block["fail"]
                cfg.add_edge(from_addr, to_addr)

        logger.debug(
            f"Built CFG for {function_name}: {len(cfg.blocks)} blocks, {len(cfg.edges)} edges"
        )

        return cfg

    def build_all_cfgs(self) -> dict[int, ControlFlowGraph]:
        """
        Build CFGs for all functions in the binary.

        Returns:
            Dictionary mapping function address to CFG
        """
        if not self.binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            self.binary.analyze()

        functions = self.binary.get_functions()
        cfgs = {}

        logger.info(f"Building CFGs for {len(functions)} functions...")

        for func in functions:
            addr = func.get("offset", 0)
            name = func.get("name", f"func_{addr:x}")

            try:
                cfg = self.build_cfg(addr, name)
                if cfg.blocks:
                    cfgs[addr] = cfg
            except Exception as e:
                logger.debug(f"Failed to build CFG for {name}: {e}")

        logger.info(f"Successfully built {len(cfgs)} CFGs")
        return cfgs
