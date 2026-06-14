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

import r2morph.analysis.cfg_models as _cfg_models
from r2morph.analysis.cfg_builder_helpers import populate_cfg_blocks, populate_cfg_edges
from r2morph.analysis.cfg_exception_helpers import detect_exception_edges
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)

BasicBlock = _cfg_models.BasicBlock
BlockType = _cfg_models.BlockType
ControlFlowGraph = _cfg_models.ControlFlowGraph
EdgeType = _cfg_models.EdgeType
ExceptionEdge = _cfg_models.ExceptionEdge
TailCall = _cfg_models.TailCall

__all__ = [
    "BasicBlock",
    "BlockType",
    "CFGBuilder",
    "ControlFlowGraph",
    "EdgeType",
    "ExceptionEdge",
    "TailCall",
]


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

        populate_cfg_blocks(cfg, self.binary, function_address, r2_blocks)
        populate_cfg_edges(cfg, r2_blocks)

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
        return detect_exception_edges(self.binary, cfg, function_address)

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
