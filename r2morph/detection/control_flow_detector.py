"""
Control flow analysis for detecting obfuscation techniques.

This module provides detection of control flow-based obfuscation including:
- Control flow flattening (CFF)
- Opaque predicates
- VM-based obfuscation
- Mixed Boolean Arithmetic (MBA) expressions
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ControlFlowAnalysisResult:
    """Result of control flow analysis."""

    cff_detected: bool = False
    cff_confidence: float = 0.0
    opaque_predicates_count: int = 0
    mba_expressions_count: int = 0
    vm_detected: bool = False
    vm_confidence: float = 0.0
    vm_handler_count: int = 0
    vm_indicators: list[str] = field(default_factory=list)
    metamorphic_detected: bool = False
    metamorphic_confidence: float = 0.0
    metamorphic_indicators: list[str] = field(default_factory=list)
    polymorphic_ratio: float = 0.0


class ControlFlowAnalyzer:
    """
    Analyzes control flow patterns to detect obfuscation.

    Detects various control flow-based obfuscation techniques
    including flattening, opaque predicates, and virtualization.
    """

    def __init__(self, binary: "Binary"):
        """
        Initialize control flow analyzer.

        Args:
            binary: Binary to analyze
        """
        self.binary = binary

    def analyze(self) -> ControlFlowAnalysisResult:
        """
        Perform comprehensive control flow analysis.

        Returns:
            ControlFlowAnalysisResult with all findings
        """
        result = ControlFlowAnalysisResult()

        # Detect control flow flattening
        result.cff_confidence = self._detect_control_flow_flattening()
        result.cff_detected = result.cff_confidence > 0.3

        # Detect opaque predicates
        result.opaque_predicates_count = self._detect_opaque_predicates()

        # Detect MBA patterns
        result.mba_expressions_count = self._detect_mba_patterns()

        # Detect virtualization
        vm_result = self._detect_virtualization()
        result.vm_detected = vm_result["detected"]
        result.vm_confidence = vm_result["confidence"]
        result.vm_handler_count = vm_result["handler_count"]
        result.vm_indicators = vm_result["indicators"]

        # Detect metamorphic code
        meta_result = self._detect_metamorphic_engine()
        result.metamorphic_detected = meta_result["detected"]
        result.metamorphic_confidence = meta_result["confidence"]
        result.metamorphic_indicators = meta_result["indicators"]
        result.polymorphic_ratio = meta_result["polymorphic_ratio"]

        return result

    def _get_function_address(self, func: dict[str, Any]) -> int:
        """Resolve a function address from r2 metadata."""
        return func.get("offset") or func.get("addr") or 0

    def _detect_control_flow_flattening(self) -> float:
        """
        Detect control flow flattening obfuscation.

        Returns:
            Confidence score for CFF detection
        """
        try:
            functions = self.binary.get_functions()
            if not functions:
                return 0.0

            cff_indicators = 0
            total_functions = 0

            for func in functions[:10]:  # Check first 10 functions
                func_addr = self._get_function_address(func)
                if func_addr == 0:
                    continue

                total_functions += 1

                # Get basic blocks for this function
                try:
                    blocks = self.binary.get_basic_blocks(func_addr)
                    if len(blocks) > 20:  # Many basic blocks might indicate flattening
                        # Check for dispatcher pattern (switch-like structure)
                        dispatcher_found = self._check_dispatcher_pattern(blocks)
                        if dispatcher_found:
                            cff_indicators += 1

                except Exception:
                    continue

            if total_functions == 0:
                return 0.0

            return cff_indicators / total_functions

        except Exception as e:
            logger.debug(f"Error detecting control flow flattening: {e}")
            return 0.0

    def _check_dispatcher_pattern(self, blocks: list[dict[str, Any]]) -> bool:
        """Check for control flow dispatcher pattern."""
        try:
            # Look for blocks with many successors (dispatcher characteristic)
            for block in blocks:
                block_addr = block.get("addr", 0)
                if block_addr == 0:
                    continue

                # Get instructions in this block
                instructions = self.binary.get_function_disasm(block_addr)

                # Look for switch/jump table patterns
                for inst in instructions:
                    disasm = inst.get("disasm", "").lower()
                    if ("jmp" in disasm and "[" in disasm) or "switch" in disasm:
                        return True

            return False

        except Exception:
            return False

    def _detect_opaque_predicates(self) -> int:
        """
        Detect opaque predicates (always true/false conditions).

        Returns:
            Number of potential opaque predicates found
        """
        opaque_count = 0

        try:
            functions = self.binary.get_functions()

            for func in functions[:10]:
                func_addr = self._get_function_address(func)
                if func_addr == 0:
                    continue

                try:
                    instructions = self.binary.get_function_disasm(func_addr)

                    # Look for suspicious conditional patterns
                    for i, inst in enumerate(instructions):
                        disasm = inst.get("disasm", "").lower()

                        # Look for comparisons followed by predictable branches
                        if "cmp" in disasm and i + 1 < len(instructions):
                            # Check for obvious always-true/false conditions
                            if "cmp" in disasm:
                                # Simple heuristic: same register compared with itself
                                parts = disasm.split(None, 1)
                                if len(parts) == 2:
                                    operands = [op.strip() for op in parts[1].split(",")]
                                    if len(operands) >= 2 and operands[0] == operands[1]:
                                        opaque_count += 1

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Error detecting opaque predicates: {e}")

        return opaque_count

    def _detect_mba_patterns(self) -> int:
        """
        Detect Mixed Boolean Arithmetic expressions.

        Returns:
            Number of MBA patterns found
        """
        mba_count = 0

        try:
            functions = self.binary.get_functions()

            for func in functions[:10]:  # Check first 10 functions
                func_addr = self._get_function_address(func)
                if func_addr == 0:
                    continue

                try:
                    instructions = self.binary.get_function_disasm(func_addr)

                    # Look for MBA patterns: complex arithmetic with boolean operations
                    bool_ops = 0
                    arith_ops = 0

                    for inst in instructions:
                        disasm = inst.get("disasm", "").lower()

                        if any(op in disasm for op in ["and", "or", "xor", "not"]):
                            bool_ops += 1

                        if any(op in disasm for op in ["add", "sub", "mul", "imul"]):
                            arith_ops += 1

                    # MBA typically has high mix of boolean and arithmetic operations
                    if bool_ops > 5 and arith_ops > 5 and len(instructions) > 0:
                        mix_ratio = (bool_ops + arith_ops) / len(instructions)
                        if mix_ratio > 0.4:  # More than 40% boolean/arithmetic mix
                            mba_count += 1

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Error detecting MBA patterns: {e}")

        return mba_count

    def _detect_virtualization(self) -> dict[str, Any]:
        """
        Detect virtual machine-based obfuscation.

        Returns:
            VM detection result with confidence and handler count
        """
        result: dict[str, Any] = {
            "detected": False,
            "confidence": 0.0,
            "handler_count": 0,
            "indicators": [],
        }

        try:
            functions = self.binary.get_functions()
            vm_indicators = 0
            total_functions = len(functions)

            if total_functions == 0:
                return result

            # Look for VM characteristics
            for func in functions[:20]:  # Check first 20 functions
                func_addr = self._get_function_address(func)
                if func_addr == 0:
                    continue

                try:
                    instructions = self.binary.get_function_disasm(func_addr)

                    # VM indicator patterns
                    indirect_jumps = 0
                    table_accesses = 0

                    for inst in instructions:
                        disasm = inst.get("disasm", "").lower()

                        # Indirect jumps through registers/memory
                        if "jmp" in disasm and any(
                            reg in disasm for reg in ["eax", "ebx", "ecx", "edx", "rax", "rbx"]
                        ):
                            indirect_jumps += 1

                        # Memory table accesses
                        if "mov" in disasm and "[" in disasm and "+" in disasm:
                            table_accesses += 1

                    # High ratio of indirect jumps suggests VM
                    if len(instructions) > 0:
                        indirect_ratio = indirect_jumps / len(instructions)
                        if indirect_ratio > 0.1:  # More than 10% indirect jumps
                            vm_indicators += 1
                            result["indicators"].append(
                                f"High indirect jump ratio in function at 0x{func_addr:x}"
                            )

                except Exception:
                    continue

            # Calculate confidence
            if total_functions > 0:
                vm_ratio = vm_indicators / min(total_functions, 20)
                result["confidence"] = vm_ratio
                result["detected"] = vm_ratio > 0.3  # 30% threshold
                result["handler_count"] = vm_indicators

        except Exception as e:
            logger.debug(f"Error detecting virtualization: {e}")

        return result

    def detect_custom_virtualizer(self) -> dict[str, Any]:
        """
        Detect custom virtualization engines.

        Returns:
            Dictionary with detection results
        """
        result: dict[str, Any] = {
            "detected": False,
            "confidence": 0.0,
            "indicators": [],
            "vm_type": "unknown",
        }

        try:
            # Look for VM-specific patterns
            patterns = {
                "register_based": [
                    b"\x8b\x45\xfc",  # mov eax, [ebp-4] - stack access
                    b"\x89\x45\xfc",  # mov [ebp-4], eax - stack store
                ],
                "stack_based": [
                    b"\x58\x59\x5a\x5b",  # pop sequence
                    b"\x50\x51\x52\x53",  # push sequence
                ],
                "bytecode_handler": [
                    b"\xfe\xc0",  # inc al - bytecode increment
                    b"\x30\xc0",  # xor al, al - bytecode reset
                ],
            }

            # Check for each pattern type
            for vm_type, type_patterns in patterns.items():
                pattern_count = 0

                for pattern in type_patterns:
                    cmd = f"/x {pattern.hex()}"
                    matches = self.binary.r2.cmd(cmd)
                    if matches:
                        pattern_count += len(matches.strip().split("\n")) if matches.strip() else 0

                if pattern_count > 10:  # Threshold for pattern detection
                    result["detected"] = True
                    result["vm_type"] = vm_type
                    result["confidence"] = min(1.0, pattern_count / 50.0)
                    result["indicators"].append(f"Found {pattern_count} {vm_type} VM patterns")
                    break

            # Additional heuristics
            if not result["detected"]:
                # Check for computed jump tables
                jump_table_patterns = [
                    b"\xff\x24\x85",  # jmp [table + reg*4]
                    b"\xff\x24\x95",  # jmp [table + reg*4] variant
                ]

                for pattern in jump_table_patterns:
                    cmd = f"/x {pattern.hex()}"
                    matches = self.binary.r2.cmd(cmd)
                    if matches and matches.strip():
                        result["detected"] = True
                        result["vm_type"] = "jump_table"
                        result["confidence"] = 0.7
                        result["indicators"].append("Found computed jump table patterns")
                        break

        except Exception as e:
            logger.error(f"Custom virtualizer detection failed: {e}")

        return result

    def _detect_metamorphic_engine(self) -> dict[str, Any]:
        """
        Detect metamorphic code generation.

        Returns:
            Dictionary with metamorphic analysis
        """
        result: dict[str, Any] = {
            "detected": False,
            "confidence": 0.0,
            "indicators": [],
            "polymorphic_ratio": 0.0,
        }

        try:
            functions = self.binary.get_functions()
            total_functions = len(functions)
            polymorphic_functions = 0

            for func in functions[:20]:  # Limit analysis for performance
                func_addr = self._get_function_address(func)

                try:
                    # Get function instructions
                    instructions = self.binary.r2.cmdj(f"pdfj @ {func_addr}")
                    if not instructions or "ops" not in instructions:
                        continue

                    ops = instructions["ops"]

                    # Look for metamorphic indicators
                    dead_code_count = 0
                    nop_count = 0
                    redundant_moves = 0

                    for op in ops:
                        opcode = op.get("opcode", "").lower()

                        # Count NOPs
                        if "nop" in opcode:
                            nop_count += 1

                        # Count redundant moves (mov reg, reg)
                        if "mov" in opcode and len(opcode.split()) >= 3:
                            parts = opcode.split()
                            if len(parts) >= 3:
                                src = parts[2].rstrip(",")
                                dst = parts[1].rstrip(",")
                                if src == dst:
                                    redundant_moves += 1

                        # Count potentially dead arithmetic
                        if any(instr in opcode for instr in ["add", "sub", "xor"]) and "0" in opcode:
                            dead_code_count += 1

                    # Calculate polymorphic score
                    total_ops = len(ops)
                    if total_ops > 0:
                        poly_score = (dead_code_count + nop_count + redundant_moves) / total_ops

                        if poly_score > 0.3:  # 30% threshold
                            polymorphic_functions += 1
                            result["indicators"].append(
                                f"Function at 0x{func_addr:x} has {poly_score:.1%} polymorphic indicators"
                            )

                except Exception:
                    continue

            # Calculate overall results
            if total_functions > 0:
                result["polymorphic_ratio"] = polymorphic_functions / total_functions

                if result["polymorphic_ratio"] > 0.2:  # 20% of functions
                    result["detected"] = True
                    result["confidence"] = min(1.0, result["polymorphic_ratio"] * 2)

        except Exception as e:
            logger.error(f"Metamorphic detection failed: {e}")

        return result
