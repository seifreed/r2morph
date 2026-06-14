"""
Control Flow Obfuscation (CFO) Simplifier for r2morph.

This module implements advanced techniques for detecting and simplifying
control flow obfuscation patterns commonly used by commercial packers
like VMProtect, Themida, and custom obfuscators.

Key Features:
- Dispatcher-based control flow flattening detection
- Switch-case obfuscation reconstruction
- Indirect jump resolution
- Opaque predicate elimination
- Control flow graph reconstruction
"""

import logging
from typing import Any

from .cfo_simplifier_detection import (
    detect_dispatcher_flattening,
    detect_fake_control_flow,
    detect_indirect_jumps,
    detect_obfuscation_patterns,
    detect_opaque_predicates,
    detect_switch_case_obfuscation,
)
from .cfo_simplifier_models import CFOPattern, CFOSimplificationResult, ControlFlowBlock, DispatcherInfo
from .cfo_simplifier_transforms import (
    analyze_dispatch_targets,
    calculate_complexity,
    eliminate_opaque_predicates,
    reconstruct_control_flow,
    remove_fake_control_flow,
    resolve_indirect_jumps,
    simplify_dispatcher_flattening,
)

nx: Any
try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

logger = logging.getLogger(__name__)


class CFOSimplifier:
    """
    Advanced Control Flow Obfuscation simplifier.

    Detects and simplifies various control flow obfuscation techniques
    used by commercial packers and custom obfuscators.
    """

    def __init__(self, binary: Any = None) -> None:
        """Initialize the CFO simplifier."""
        self.binary = binary
        self.blocks: dict[int, Any] = {}
        self.cfg: Any = None
        self.dispatchers: list[Any] = []

        # Pattern detection thresholds
        self.dispatcher_threshold = 0.7
        self.opaque_predicate_threshold = 0.8

        # Analysis cache
        self._analysis_cache: dict[int, Any] = {}

        if not NETWORKX_AVAILABLE:
            logger.warning("NetworkX not available - CFG analysis will be limited")

    def simplify_control_flow(self, function_address: int, max_iterations: int = 10) -> CFOSimplificationResult:
        """
        Simplify control flow obfuscation in a function.

        Args:
            function_address: Address of the function to analyze
            max_iterations: Maximum number of simplification iterations

        Returns:
            CFOSimplificationResult with analysis results
        """
        import time

        start_time = time.time()

        try:
            logger.info(f"Starting CFO simplification for function at 0x{function_address:x}")

            # Build initial control flow graph
            self._build_cfg(function_address)
            original_complexity = self._calculate_complexity()

            # Detect obfuscation patterns
            patterns = self._detect_obfuscation_patterns()

            if not patterns:
                return CFOSimplificationResult(
                    success=True,
                    original_complexity=original_complexity,
                    simplified_complexity=original_complexity,
                    execution_time=time.time() - start_time,
                    warnings=["No obfuscation patterns detected"],
                )

            # Apply simplification techniques iteratively
            for iteration in range(max_iterations):
                logger.debug(f"CFO simplification iteration {iteration + 1}")

                changes_made = False

                # Apply each simplification technique
                if CFOPattern.DISPATCHER_FLATTENING in patterns:
                    if self._simplify_dispatcher_flattening():
                        changes_made = True

                if CFOPattern.OPAQUE_PREDICATES in patterns:
                    if self._eliminate_opaque_predicates():
                        changes_made = True

                if CFOPattern.INDIRECT_JUMPS in patterns:
                    if self._resolve_indirect_jumps():
                        changes_made = True

                if CFOPattern.FAKE_CONTROL_FLOW in patterns:
                    if self._remove_fake_control_flow():
                        changes_made = True

                # Check for convergence
                if not changes_made:
                    logger.debug(f"CFO simplification converged after {iteration + 1} iterations")
                    break

            simplified_complexity = self._calculate_complexity()

            return CFOSimplificationResult(
                success=True,
                patterns_detected=patterns,
                simplified_blocks=self.blocks.copy(),
                original_complexity=original_complexity,
                simplified_complexity=simplified_complexity,
                dispatcher_info=self.dispatchers.copy(),
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            logger.error(f"CFO simplification failed: {e}")
            return CFOSimplificationResult(
                success=False, execution_time=time.time() - start_time, warnings=[f"Simplification failed: {str(e)}"]
            )

    def _build_cfg(self, function_address: int) -> None:
        """Build control flow graph for the function."""
        if not self.binary:
            logger.warning("No binary object available for CFG analysis")
            return

        try:
            # Get function information from r2
            self.binary.r2.cmd(f"s {function_address}")

            # Analyze function and get basic blocks
            func_info = self.binary.r2.cmdj(f"afij @ {function_address}")
            if not func_info:
                logger.warning(f"Could not analyze function at 0x{function_address:x}")
                return

            # Get basic blocks
            blocks_info = self.binary.r2.cmdj(f"afbj @ {function_address}")
            if not blocks_info:
                logger.warning("No basic blocks found")
                return

            # Build block objects
            for block_info in blocks_info:
                address = block_info.get("addr", 0)

                # Get instructions for this block
                instructions = self.binary.r2.cmdj(f"pdj {block_info.get('ninstr', 0)} @ {address}")
                if not instructions:
                    instructions = []

                # Create block object
                block = ControlFlowBlock(address=address, instructions=instructions)

                # Add successors
                if "jump" in block_info:
                    block.successors.add(block_info["jump"])
                if "fail" in block_info:
                    block.successors.add(block_info["fail"])

                self.blocks[address] = block

            # Build predecessor relationships
            for address, block in self.blocks.items():
                for successor in block.successors:
                    if successor in self.blocks:
                        self.blocks[successor].predecessors.add(address)

            # Build NetworkX graph if available
            if NETWORKX_AVAILABLE:
                self.cfg = nx.DiGraph()
                for address, block in self.blocks.items():
                    self.cfg.add_node(address)
                    for successor in block.successors:
                        self.cfg.add_edge(address, successor)

            logger.debug(f"Built CFG with {len(self.blocks)} blocks")

        except Exception as e:
            logger.error(f"Failed to build CFG: {e}")

    def _detect_obfuscation_patterns(self) -> list[CFOPattern]:
        return detect_obfuscation_patterns(self)

    def _detect_dispatcher_flattening(self) -> bool:
        return detect_dispatcher_flattening(self)

    def _detect_opaque_predicates(self) -> bool:
        return detect_opaque_predicates(self)

    def _detect_indirect_jumps(self) -> bool:
        return detect_indirect_jumps(self)

    def _detect_fake_control_flow(self) -> bool:
        return detect_fake_control_flow(self)

    def _detect_switch_case_obfuscation(self) -> bool:
        return detect_switch_case_obfuscation(self)

    def _simplify_dispatcher_flattening(self) -> bool:
        return simplify_dispatcher_flattening(self)

    def _eliminate_opaque_predicates(self) -> bool:
        return eliminate_opaque_predicates(self)

    def _resolve_indirect_jumps(self) -> bool:
        return resolve_indirect_jumps(self)

    def _remove_fake_control_flow(self) -> bool:
        return remove_fake_control_flow(self)

    def _analyze_dispatch_targets(self, dispatcher_info: DispatcherInfo) -> None:
        analyze_dispatch_targets(self, dispatcher_info)

    def _reconstruct_control_flow(self, dispatcher: DispatcherInfo) -> list[tuple[int, int]]:
        return reconstruct_control_flow(self, dispatcher)

    def _calculate_complexity(self) -> int:
        return calculate_complexity(self)

    def _is_constant_expression(self, op1: str, op2: str) -> bool:
        """Check if operands form a constant expression."""
        try:
            # Simple heuristics for constant expressions
            if op1.isdigit() and op2.isdigit():
                return True

            # Check for mathematical identities (x - x, x ^ x, etc.)
            if op1 == op2:
                return True

            return False

        except Exception:
            return False

    def _is_opaque_comparison(self, instr: dict[str, Any]) -> bool:
        """Check if an instruction represents an opaque comparison."""
        try:
            opcode = instr.get("opcode", "").lower()

            if "cmp" not in opcode and "test" not in opcode:
                return False

            operands = instr.get("operands", [])
            if len(operands) < 2:
                return False

            op1 = operands[0].get("value", "")
            op2 = operands[1].get("value", "")

            return self._is_constant_expression(op1, op2)

        except Exception:
            return False

    def _resolve_jump_target(self, instr: dict[str, Any]) -> int | None:
        """Try to resolve indirect jump target."""
        try:
            # Simplified implementation for indirect jump analysis
            # Advanced pattern recognition for complex obfuscation
            opcode = instr.get("opcode", "")

            # Look for simple patterns like jmp [reg+offset]
            if "[" in opcode and "]" in opcode:
                # Extract the memory reference
                mem_ref = opcode[opcode.find("[") + 1 : opcode.find("]")]

                # Try to resolve simple cases
                if mem_ref.isdigit():
                    try:
                        return int(mem_ref, 16) if "x" in mem_ref else int(mem_ref)
                    except ValueError:
                        # Not a parseable numeric literal here (e.g. register/symbolic operand); expected, so this candidate is skipped.
                        pass

            return None

        except Exception:
            return None

    def _extract_state_value(self, block: ControlFlowBlock) -> int | None:
        """Extract state value from a block."""
        try:
            # Look for immediate values in the first few instructions
            for instr in block.instructions[:3]:
                operands = instr.get("operands", [])
                for operand in operands:
                    value = operand.get("value", "")
                    if value.isdigit():
                        return int(value)
                    elif "x" in value:
                        try:
                            return int(value, 16)
                        except ValueError:
                            continue

            return None

        except Exception:
            return None

    def _find_state_setters(self, state_value: int, state_variable: str) -> list[int]:
        """Find blocks that set a specific state value."""
        try:
            setters = []

            for address, block in self.blocks.items():
                for instr in block.instructions:
                    opcode = instr.get("opcode", "").lower()

                    # Look for mov instructions that set the state variable
                    if "mov" in opcode:
                        operands = instr.get("operands", [])
                        if len(operands) >= 2:
                            dest = operands[0].get("value", "")
                            src = operands[1].get("value", "")

                            if state_variable in dest and str(state_value) in src:
                                setters.append(address)
                                break

            return setters

        except Exception:
            return []
