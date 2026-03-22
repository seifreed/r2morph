"""
Control Flow Graph (CFG) analysis for binary functions.

Provides graph-based representations of program control flow.
Includes support for:
- Basic blocks and edges
- Dominator analysis
- Loop detection
- Tail call detection
- Exception edge handling
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


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
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.error(f"Failed to get basic blocks for function @ 0x{function_address:x}: {e}")
            return cfg

        for r2_block in r2_blocks:
            addr = r2_block.get("addr", 0)
            size = r2_block.get("size", 0)

            block_type = BlockType.NORMAL
            if r2_block.get("fail"):
                block_type = BlockType.CONDITIONAL
            elif r2_block.get("type") == "call":
                block_type = BlockType.CALL

            instructions = []
            try:
                all_instrs = self.binary.get_function_disasm(function_address)
                instructions = [insn for insn in all_instrs if addr <= insn.get("offset", 0) < addr + size]
            except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                logger.debug(f"Could not get instructions for block at 0x{addr:x}: {e}")

            block = BasicBlock(
                address=addr,
                size=size,
                instructions=instructions,
                successors=[],
                predecessors=[],
                block_type=block_type,
            )

            cfg.add_block(block)

        for r2_block in r2_blocks:
            from_addr = r2_block.get("addr", 0)

            if r2_block.get("jump"):
                to_addr = r2_block["jump"]
                edge_type = EdgeType.NORMAL
                src_block = cfg.get_block(from_addr)
                if src_block:
                    terminal = src_block.get_terminal_instruction()
                    if terminal:
                        mnemonic = terminal.get("type", "").lower()
                        if mnemonic == "ujmp":
                            edge_type = EdgeType.INDIRECT
                        elif mnemonic == "cjmp":
                            edge_type = EdgeType.CONDITIONAL_TRUE
                        elif mnemonic in ("jmp", "call"):
                            edge_type = EdgeType.NORMAL
                        else:
                            edge_type = EdgeType.NORMAL
                cfg.add_edge(from_addr, to_addr, edge_type)

            if r2_block.get("fail"):
                to_addr = r2_block["fail"]
                fail_block = cfg.get_block(from_addr)
                edge_type = EdgeType.CONDITIONAL_FALSE
                if fail_block:
                    terminal = fail_block.get_terminal_instruction()
                    if terminal:
                        mnemonic = terminal.get("type", "").lower()
                        if mnemonic == "cjmp":
                            edge_type = EdgeType.CONDITIONAL_FALSE
                cfg.add_edge(from_addr, to_addr, edge_type)

        self._detect_tail_calls(cfg, function_address)

        logger.debug(f"Built CFG for {function_name}: {len(cfg.blocks)} blocks, {len(cfg.edges)} edges")

        return cfg

    def _detect_tail_calls(self, cfg: ControlFlowGraph, function_address: int) -> None:
        """
        Detect tail calls in a CFG.

        A tail call is a jmp instruction that targets another function's entry point.

        Args:
            cfg: ControlFlowGraph to analyze
            function_address: Address of the function being analyzed
        """
        functions = {}
        try:
            func_list = self.binary.get_functions()
            for func in func_list:
                addr = func.get("offset", 0)
                name = func.get("name", "")
                if addr:
                    functions[addr] = name
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to get functions for tail call detection: {e}")

        for addr, block in cfg.blocks.items():
            terminal = block.get_terminal_instruction()
            if not terminal:
                continue

            mnemonic = terminal.get("type", "").lower()
            if mnemonic != "jmp":
                continue

            jump_addr = terminal.get("jump")
            if not jump_addr:
                continue

            if jump_addr in functions and jump_addr != function_address:
                tail_call = TailCall(
                    source_address=addr,
                    target_address=jump_addr,
                    source_function=function_address,
                    target_function=jump_addr,
                    target_name=functions.get(jump_addr, ""),
                )
                cfg.add_tail_call(tail_call)
                block.metadata["tail_call"] = jump_addr
                logger.debug(
                    f"Detected tail call at 0x{addr:x} -> 0x{jump_addr:x} ({functions.get(jump_addr, 'unknown')})"
                )

    def detect_exception_edges(self, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:
        """
        Detect exception handling edges in a function.

        This requires platform-specific analysis:
        - ELF: .eh_frame section parsing
        - PE: .pdata section parsing
        - Mach-O: __unwind_info section

        Args:
            cfg: ControlFlowGraph to analyze
            function_address: Address of the function

        Returns:
            List of detected ExceptionEdge instances
        """
        exception_edges: list[ExceptionEdge] = []

        arch_info = self.binary.get_arch_info()
        binary_format = arch_info.get("format", "")

        if binary_format.startswith("ELF"):
            exception_edges = self._detect_elf_exception_edges(cfg, function_address)
        elif binary_format in ("PE", "PE+"):
            exception_edges = self._detect_pe_exception_edges(cfg, function_address)
        elif binary_format in ("Mach-O", "Mach-O-64"):
            exception_edges = self._detect_macho_exception_edges(cfg, function_address)

        for edge in exception_edges:
            cfg.add_exception_edge(edge)

        return exception_edges

    def _detect_elf_exception_edges(self, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:
        """
        Detect exception edges from ELF .eh_frame.

        Args:
            cfg: ControlFlowGraph
            function_address: Function address

        Returns:
            List of ExceptionEdge instances
        """
        exception_edges: list[ExceptionEdge] = []

        try:
            if self.binary.r2 is None:
                return exception_edges
            functions = self.binary.r2.cmdj("aflj")
            if not functions:
                return exception_edges

            landing_pads = set()
            for func in functions if isinstance(functions, list) else []:
                func_addr = func.get("addr", func.get("offset", 0))
                if func_addr == function_address:
                    landing_pads.update(func.get("landing_pads", []))

            blocks = list(cfg.blocks.values())
            for block in blocks:
                if block.address in landing_pads:
                    block.block_type = BlockType.LANDING_PAD
                    block.metadata["is_landing_pad"] = True
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to detect ELF exception edges: {e}")

        return exception_edges

    def _detect_pe_exception_edges(self, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:
        """
        Detect exception edges from PE .pdata.

        Args:
            cfg: ControlFlowGraph
            function_address: Function address

        Returns:
            List of ExceptionEdge instances
        """
        exception_edges: list[ExceptionEdge] = []

        return exception_edges

    def _detect_macho_exception_edges(self, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:
        """
        Detect exception edges from Mach-O __unwind_info.

        Args:
            cfg: ControlFlowGraph
            function_address: Function address

        Returns:
            List of ExceptionEdge instances
        """
        exception_edges: list[ExceptionEdge] = []

        return exception_edges

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
            except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                logger.debug(f"Failed to build CFG for {name}: {e}")

        logger.info(f"Successfully built {len(cfgs)} CFGs")
        return cfgs
