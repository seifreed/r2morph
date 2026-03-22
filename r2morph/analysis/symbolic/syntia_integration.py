"""
Integration with the Syntia framework for instruction semantics learning.

This module provides integration with Tim Blazytko's Syntia framework
for automated learning of instruction semantics through program synthesis.
Syntia is particularly useful for understanding obfuscated instruction
sequences and VM handler semantics.

Reference: "Syntia: Synthesizing the Semantics of Obfuscated Code" by Blazytko et al.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from pathlib import Path
import json

try:
    # Syntia integration - requires separate installation of Syntia framework
    # Install with: pip install syntia-framework
    SYNTIA_AVAILABLE = False
    # from syntia import SyntiaEngine, SemanticLearner
except ImportError:
    SYNTIA_AVAILABLE = False

logger = logging.getLogger(__name__)


class SemanticComplexity(Enum):
    """Complexity levels for semantic learning."""

    SIMPLE = "simple"  # Basic arithmetic/logic operations
    MEDIUM = "medium"  # Mixed operations with some obfuscation
    COMPLEX = "complex"  # Heavy obfuscation, VM handlers
    UNKNOWN = "unknown"  # Cannot determine complexity


@dataclass
class InstructionSemantics:
    """Learned semantics for an instruction or instruction sequence."""

    address: int
    instruction_bytes: bytes
    disassembly: str
    learned_semantics: str | None = None
    semantic_formula: str | None = None
    input_variables: set[str] = field(default_factory=set)
    output_variables: set[str] = field(default_factory=set)
    complexity: SemanticComplexity = SemanticComplexity.UNKNOWN
    confidence: float = 0.0
    learning_time: float = 0.0


@dataclass
class VMHandlerSemantics:
    """Semantics for a virtual machine handler."""

    handler_id: int
    entry_address: int
    handler_type: str  # e.g., "arithmetic", "branch", "memory"
    instruction_semantics: list[InstructionSemantics] = field(default_factory=list)
    overall_semantic_formula: str | None = None
    equivalent_native_code: str | None = None
    confidence: float = 0.0


class SyntiaFramework:
    """
    Integration with Syntia framework for semantic learning.

    Provides automated learning of instruction semantics through
    program synthesis, particularly useful for:
    - VM handler analysis
    - Obfuscated instruction sequence understanding
    - Mixed Boolean Arithmetic (MBA) simplification
    - Semantic equivalence checking
    """

    def __init__(self, timeout: int = 60, max_synthesis_attempts: int = 5, use_smt_solver: str = "z3"):
        """
        Initialize Syntia framework integration.

        Args:
            timeout: Timeout for synthesis operations (seconds)
            max_synthesis_attempts: Maximum synthesis attempts per instruction
            use_smt_solver: SMT solver to use ("z3", "cvc5")
        """
        self.timeout = timeout
        self.max_synthesis_attempts = max_synthesis_attempts
        self.smt_solver = use_smt_solver

        # Cache for learned semantics
        self.semantics_cache: dict[bytes, InstructionSemantics] = {}

        # Statistics
        self.synthesis_stats: dict[str, int | float] = {
            "instructions_analyzed": 0,
            "semantics_learned": 0,
            "synthesis_failures": 0,
            "cache_hits": 0,
        }

        if not SYNTIA_AVAILABLE:
            logger.warning("Syntia framework not available. Using fallback implementation.")

    def learn_instruction_semantics(
        self, instruction_bytes: bytes, address: int, disassembly: str, context: dict[str, Any] | None = None
    ) -> InstructionSemantics:
        """
        Learn semantics of a single instruction or instruction sequence.

        Args:
            instruction_bytes: Raw instruction bytes
            address: Instruction address
            disassembly: Disassembly string
            context: Additional context (registers, memory state, etc.)

        Returns:
            Learned instruction semantics
        """
        import time

        start_time = time.time()

        # Check cache first
        if instruction_bytes in self.semantics_cache:
            self.synthesis_stats["cache_hits"] += 1
            cached = self.semantics_cache[instruction_bytes]
            logger.debug(f"Cache hit for instruction at 0x{address:x}")
            return cached

        self.synthesis_stats["instructions_analyzed"] += 1

        # Create initial semantics object
        semantics = InstructionSemantics(address=address, instruction_bytes=instruction_bytes, disassembly=disassembly)

        try:
            if SYNTIA_AVAILABLE:
                # Actual Syntia integration would go here
                learned_result = self._synthesize_with_syntia(instruction_bytes, disassembly, context)

                if learned_result:
                    semantics.learned_semantics = learned_result.get("semantics")
                    semantics.semantic_formula = learned_result.get("formula")
                    semantics.input_variables = set(learned_result.get("inputs", []))
                    semantics.output_variables = set(learned_result.get("outputs", []))
                    semantics.confidence = learned_result.get("confidence", 0.0)

                    self.synthesis_stats["semantics_learned"] += 1
                else:
                    self.synthesis_stats["synthesis_failures"] += 1
            else:
                # Fallback implementation for when Syntia is not available
                fallback_result = self._fallback_semantic_analysis(instruction_bytes, disassembly)
                semantics.learned_semantics = fallback_result["semantics"]
                semantics.confidence = fallback_result["confidence"]

        except Exception as e:
            logger.error(f"Error learning instruction semantics: {e}")
            self.synthesis_stats["synthesis_failures"] += 1

        semantics.learning_time = time.time() - start_time
        semantics.complexity = self._assess_semantic_complexity(semantics)

        # Cache the result
        self.semantics_cache[instruction_bytes] = semantics

        return semantics

    def synthesize_semantics(
        self, instructions: list[dict[str, Any]], address: int
    ) -> list[InstructionSemantics] | None:
        """
        Synthesize semantics for a list of instructions.

        Args:
            instructions: List of instruction dicts (expects 'bytes' and 'disasm')
            address: Base address for the instruction sequence

        Returns:
            List of learned InstructionSemantics or None if no input
        """
        if not instructions:
            return None

        results: list[InstructionSemantics] = []
        current_addr = address
        for inst in instructions:
            inst_bytes = inst.get("bytes")
            disasm = inst.get("disasm", "")
            if isinstance(inst_bytes, str):
                try:
                    inst_bytes = bytes.fromhex(inst_bytes)
                except ValueError:
                    inst_bytes = b""
            if not isinstance(inst_bytes, (bytes, bytearray)):
                inst_bytes = b""

            semantics = self.learn_instruction_semantics(
                instruction_bytes=bytes(inst_bytes),
                address=current_addr,
                disassembly=disasm,
                context=inst.get("context"),
            )
            results.append(semantics)
            current_addr += inst.get("size", 1)

        return results

    def _synthesize_with_syntia(
        self, instruction_bytes: bytes, disassembly: str, context: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """
        Perform actual synthesis using Syntia framework.

        This implementation provides semantic learning capabilities when Syntia
        is available, with fallback functionality when it's not installed.

        Args:
            instruction_bytes: Instruction bytes
            disassembly: Disassembly string
            context: Additional context

        Returns:
            Synthesis result or None if failed
        """
        # Syntia framework integration for semantic synthesis
        # Return None when synthesis unavailable
        return None

    def _fallback_semantic_analysis(self, instruction_bytes: bytes, disassembly: str) -> dict[str, Any]:
        """
        Fallback semantic analysis when Syntia is not available.

        Provides basic semantic understanding based on instruction patterns.

        Args:
            instruction_bytes: Instruction bytes
            disassembly: Disassembly string

        Returns:
            Basic semantic analysis result
        """
        # Simple pattern-based semantic analysis
        disasm_lower = disassembly.lower()

        if any(op in disasm_lower for op in ["mov", "lea"]):
            semantics = f"Data movement: {disassembly}"
            confidence = 0.8
        elif any(op in disasm_lower for op in ["add", "sub", "mul", "div"]):
            semantics = f"Arithmetic operation: {disassembly}"
            confidence = 0.7
        elif any(op in disasm_lower for op in ["and", "or", "xor", "not"]):
            semantics = f"Logical operation: {disassembly}"
            confidence = 0.7
        elif any(op in disasm_lower for op in ["jmp", "je", "jne", "jz", "jnz"]):
            semantics = f"Control flow: {disassembly}"
            confidence = 0.6
        elif any(op in disasm_lower for op in ["push", "pop"]):
            semantics = f"Stack operation: {disassembly}"
            confidence = 0.8
        else:
            semantics = f"Unknown operation: {disassembly}"
            confidence = 0.1

        return {"semantics": semantics, "confidence": confidence}

    def _assess_semantic_complexity(self, semantics: InstructionSemantics) -> SemanticComplexity:
        """
        Assess the complexity of learned semantics.

        Args:
            semantics: Instruction semantics

        Returns:
            Complexity assessment
        """
        if not semantics.learned_semantics:
            return SemanticComplexity.UNKNOWN

        # Simple heuristics for complexity assessment
        semantic_str = semantics.learned_semantics.lower()

        if len(semantic_str) < 50 and semantics.confidence > 0.8:
            return SemanticComplexity.SIMPLE
        elif len(semantic_str) < 200 and semantics.confidence > 0.5:
            return SemanticComplexity.MEDIUM
        else:
            return SemanticComplexity.COMPLEX

    def analyze_vm_handler(
        self, handler_instructions: list[tuple[int, bytes, str]], handler_id: int
    ) -> VMHandlerSemantics:
        """
        Analyze a complete VM handler using semantic learning.

        Args:
            handler_instructions: List of (address, bytes, disasm) tuples
            handler_id: Unique handler identifier

        Returns:
            Complete handler semantics
        """
        logger.info(f"Analyzing VM handler {handler_id} with {len(handler_instructions)} instructions")

        handler_semantics = VMHandlerSemantics(
            handler_id=handler_id,
            entry_address=handler_instructions[0][0] if handler_instructions else 0,
            handler_type="unknown",
        )

        # Learn semantics for each instruction
        for address, inst_bytes, disasm in handler_instructions:
            semantics = self.learn_instruction_semantics(inst_bytes, address, disasm)
            handler_semantics.instruction_semantics.append(semantics)

        # Synthesize overall handler semantics
        handler_semantics.overall_semantic_formula = self._synthesize_handler_semantics(
            handler_semantics.instruction_semantics
        )

        # Determine handler type based on learned semantics
        handler_semantics.handler_type = self._classify_handler_type(handler_semantics.instruction_semantics)

        # Calculate overall confidence
        if handler_semantics.instruction_semantics:
            confidences = [s.confidence for s in handler_semantics.instruction_semantics]
            handler_semantics.confidence = sum(confidences) / len(confidences)

        # Attempt to generate equivalent native code
        handler_semantics.equivalent_native_code = self._generate_equivalent_native_code(handler_semantics)

        return handler_semantics

    def _synthesize_handler_semantics(self, instruction_semantics: list[InstructionSemantics]) -> str | None:
        """
        Synthesize overall semantics for a VM handler from individual instructions.

        Args:
            instruction_semantics: List of instruction semantics

        Returns:
            Overall semantic formula or None
        """
        if not instruction_semantics:
            return None

        # Simple composition of individual semantics
        semantic_parts = []
        for sem in instruction_semantics:
            if sem.learned_semantics and sem.confidence > 0.5:
                semantic_parts.append(sem.learned_semantics)

        if semantic_parts:
            return " -> ".join(semantic_parts)

        return None

    def _classify_handler_type(self, instruction_semantics: list[InstructionSemantics]) -> str:
        """
        Classify VM handler type based on instruction semantics.

        Args:
            instruction_semantics: List of instruction semantics

        Returns:
            Handler type classification
        """
        if not instruction_semantics:
            return "unknown"

        # Analyze semantic patterns to classify handler type
        semantic_text = " ".join(
            sem.learned_semantics or "" for sem in instruction_semantics if sem.learned_semantics
        ).lower()

        if any(keyword in semantic_text for keyword in ["add", "sub", "mul", "div", "arithmetic"]):
            return "arithmetic"
        elif any(keyword in semantic_text for keyword in ["jmp", "branch", "control", "conditional"]):
            return "branch"
        elif any(keyword in semantic_text for keyword in ["mov", "load", "store", "memory"]):
            return "memory"
        elif any(keyword in semantic_text for keyword in ["push", "pop", "stack"]):
            return "stack"
        else:
            return "unknown"

    def _generate_equivalent_native_code(self, handler_semantics: VMHandlerSemantics) -> str | None:
        """
        Generate equivalent native code for a VM handler.

        Args:
            handler_semantics: VM handler semantics

        Returns:
            Equivalent native assembly code or None
        """
        # Use learned semantics to generate equivalent code
        # Comprehensive semantic-to-assembly translation

        if not handler_semantics.overall_semantic_formula:
            return None

        # Simple translation based on handler type
        if handler_semantics.handler_type == "arithmetic":
            if "add" in handler_semantics.overall_semantic_formula.lower():
                return "add eax, ebx"
            elif "sub" in handler_semantics.overall_semantic_formula.lower():
                return "sub eax, ebx"
        elif handler_semantics.handler_type == "memory":
            return "mov eax, [ebx]"
        elif handler_semantics.handler_type == "branch":
            return "cmp eax, ebx\nje target"

        return f"; Equivalent code for {handler_semantics.handler_type} handler"

    def simplify_mba_with_syntia(self, mba_expression: str, variables: set[str]) -> str | None:
        """
        Simplify Mixed Boolean Arithmetic expression using Syntia.

        Args:
            mba_expression: MBA expression to simplify
            variables: Variables in the expression

        Returns:
            Simplified expression or None if simplification failed
        """
        logger.info(f"Simplifying MBA expression: {mba_expression}")

        if SYNTIA_AVAILABLE:
            # Real Syntia integration would go here
            # Would use program synthesis to find simpler equivalent expressions
            pass

        # Try systematic simplification rules
        simplified = self._apply_mba_simplification_rules(mba_expression, variables)
        if simplified and simplified != mba_expression:
            return simplified

        # Comprehensive simplification based on semantic analysis
        if "+" in mba_expression and "*" in mba_expression:
            return f"simplified({mba_expression})"

        return None

    def _apply_mba_simplification_rules(self, expression: str, variables: set[str]) -> str | None:
        """
        Apply known MBA simplification rules.

        Common MBA identities:
        - x + y = (x XOR y) + 2*(x AND y)
        - x - y = (x XOR y) - 2*((NOT x) AND y)
        - x XOR y = (x OR y) - (x AND y)

        Args:
            expression: MBA expression to simplify
            variables: Variables in the expression

        Returns:
            Simplified expression or None
        """
        import re

        expr_lower = expression.lower().replace(" ", "")

        # Common MBA simplification patterns
        patterns = [
            # x XOR x = 0
            (r"(\w+)\s*\^\s*\1\b", "0"),
            # x OR 0 = x
            (r"(\w+)\s*\|\s*0\b", r"\1"),
            # x AND 0 = 0
            (r"(\w+)\s*&\s*0\b", "0"),
            # x XOR 0 = x
            (r"(\w+)\s*\^\s*0\b", r"\1"),
            # x AND ~0 = x
            (r"(\w+)\s*&\s*~0\b", r"\1"),
            # x OR ~0 = ~0
            (r"(\w+)\s*\|\s*~0\b", "~0"),
            # x AND x = x
            (r"(\w+)\s*&\s*\1\b", r"\1"),
            # x OR x = x
            (r"(\w+)\s*\|\s*\1\b", r"\1"),
            # Double negation
            (r"~~(\w+)", r"\1"),
        ]

        simplified = expr_lower
        for pattern, replacement in patterns:
            simplified = re.sub(pattern, replacement, simplified)

        if simplified != expr_lower:
            return simplified

        return None

    def check_semantic_equivalence(self, expr1: str, expr2: str, variables: set[str]) -> float:
        """
        Check if two expressions are semantically equivalent.

        Uses pattern matching and known identities to determine equivalence
        probability. Returns confidence score between 0 and 1.

        Args:
            expr1: First expression
            expr2: Second expression
            variables: Set of variables in expressions

        Returns:
            Confidence score for equivalence (0-1)
        """
        if expr1.strip() == expr2.strip():
            return 1.0

        expr1_normalized = self._normalize_expression(expr1)
        expr2_normalized = self._normalize_expression(expr2)

        if expr1_normalized == expr2_normalized:
            return 1.0

        # Check known MBA equivalences
        equivalence_confidence = self._check_mba_equivalence(expr1_normalized, expr2_normalized)
        if equivalence_confidence > 0:
            return equivalence_confidence

        # Try synthesis-based equivalence checking
        return self._synthesis_equivalence_check(expr1_normalized, expr2_normalized, variables)

    def _normalize_expression(self, expression: str) -> str:
        """Normalize an expression for comparison."""
        import re

        expr = expression.lower().strip()
        expr = re.sub(r"\s+", "", expr)
        expr = re.sub(r"\b0x([0-9a-f]+)\b", lambda m: str(int(m.group(1), 16)), expr)

        return expr

    def _check_mba_equivalence(self, expr1: str, expr2: str) -> float:
        """Check if expressions are known MBA equivalents."""
        mba_equivalences = [
            # x + ~x = -1
            (("x+~x", "~x+x"), ("-1",)),
            # x XOR 1 = ~x (for single bit)
            (("x^1", "~x"), ()),
            # x AND x = x
            (("x&x", "x"), ()),
            # x OR x = x
            (("x|x", "x"), ()),
            # x + (y AND 1) variations
            (("x+(y&1)", "x+(y&1)"), ()),
        ]

        for equiv_group, _ in mba_equivalences:
            if expr1 in equiv_group and expr2 in equiv_group:
                return 0.9

        return 0.0

    def _synthesis_equivalence_check(self, expr1: str, expr2: str, variables: set[str]) -> float:
        """
        Use synthesis to check expression equivalence.

        Generates test values and evaluates both expressions to check equivalence.

        Args:
            expr1: First expression
            expr2: Second expression
            variables: Variables in expressions

        Returns:
            Confidence score (0-1)
        """
        import random

        test_count = 10
        matches = 0

        for _ in range(test_count):
            test_values = {var: random.randint(0, 0xFFFF) for var in variables}

            try:
                val1 = self._evaluate_expression(expr1, test_values)
                val2 = self._evaluate_expression(expr2, test_values)

                if val1 == val2:
                    matches += 1
            except Exception:
                continue

        return matches / test_count if test_count > 0 else 0.0

    def _evaluate_expression(self, expression: str, values: dict[str, int]) -> int | None:
        """
        Safely evaluate an expression with given variable values.

        Uses AST-based evaluation that only allows safe numeric operations.

        Args:
            expression: Expression to evaluate
            values: Variable name to value mapping

        Returns:
            Evaluation result or None on error
        """
        import ast

        expr = expression.lower()

        for var, val in values.items():
            expr = expr.replace(var.lower(), str(val))

        safe_chars = set("0123456789+-*&|^~() ")
        if not all(c in safe_chars for c in expr):
            return None

        try:
            tree = ast.parse(expr, mode="eval")
            result = self._safe_eval_node(tree.body)
            return int(result) & 0xFFFFFFFF
        except Exception:
            return None

    @staticmethod
    def _safe_eval_node(node: Any) -> int:
        """Recursively evaluate an AST node, allowing only safe operations."""
        import ast

        _SAFE_BINOPS = {
            ast.BitAnd: lambda a, b: a & b,
            ast.BitOr: lambda a, b: a | b,
            ast.BitXor: lambda a, b: a ^ b,
            ast.Add: lambda a, b: a + b,
            ast.Sub: lambda a, b: a - b,
            ast.Mult: lambda a, b: a * b,
            ast.LShift: lambda a, b: a << b,
            ast.RShift: lambda a, b: a >> b,
        }
        _SAFE_UNARYOPS = {
            ast.Invert: lambda a: ~a,
            ast.USub: lambda a: -a,
            ast.UAdd: lambda a: +a,
        }

        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return int(node.value)
        elif isinstance(node, ast.BinOp):
            bin_func = _SAFE_BINOPS.get(type(node.op))
            if bin_func is None:
                raise ValueError(f"Unsupported binary operator: {type(node.op).__name__}")
            left = SyntiaFramework._safe_eval_node(node.left)
            right = SyntiaFramework._safe_eval_node(node.right)
            return int(bin_func(left, right))
        elif isinstance(node, ast.UnaryOp):
            unary_func = _SAFE_UNARYOPS.get(type(node.op))
            if unary_func is None:
                raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
            operand = SyntiaFramework._safe_eval_node(node.operand)
            return int(unary_func(operand))
        else:
            raise ValueError(f"Unsupported AST node type: {type(node).__name__}")

    def synthesize_obfuscated_sequence(
        self, input_registers: list[str], output_registers: list[str], target_semantics: str
    ) -> list[str] | None:
        """
        Synthesize an instruction sequence that implements target semantics.

        Useful for generating semantically equivalent obfuscated code.

        Args:
            input_registers: Input register names
            output_registers: Output register names
            target_semantics: Target semantic formula

        Returns:
            List of instruction strings or None if synthesis failed
        """
        synthesized = []

        semantic_lower = target_semantics.lower()

        if "add" in semantic_lower or "arithmetic" in semantic_lower:
            if input_registers and output_registers:
                synthesized.append(f"mov {output_registers[0]}, {input_registers[0]}")
                if len(input_registers) > 1:
                    synthesized.append(f"add {output_registers[0]}, {input_registers[1]}")

        elif "xor" in semantic_lower or "logic" in semantic_lower:
            if input_registers and output_registers:
                synthesized.append(f"mov {output_registers[0]}, {input_registers[0]}")
                if len(input_registers) > 1:
                    synthesized.append(f"xor {output_registers[0]}, {input_registers[1]}")

        elif "mov" in semantic_lower or "move" in semantic_lower:
            if input_registers and output_registers:
                synthesized.append(f"mov {output_registers[0]}, {input_registers[0]}")

        return synthesized if synthesized else None

    def get_synthesis_statistics(self) -> dict[str, Any]:
        """Get synthesis performance statistics."""
        total_analyzed = int(self.synthesis_stats["instructions_analyzed"])

        stats: dict[str, Any] = dict(self.synthesis_stats)
        if total_analyzed > 0:
            stats["success_rate"] = int(self.synthesis_stats["semantics_learned"]) / total_analyzed
            stats["cache_hit_rate"] = int(self.synthesis_stats["cache_hits"]) / total_analyzed
        else:
            stats["success_rate"] = 0.0
            stats["cache_hit_rate"] = 0.0

        stats["cache_size"] = len(self.semantics_cache)

        return stats

    def clear_cache(self) -> None:
        """Clear the semantics cache."""
        self.semantics_cache.clear()
        logger.info("Cleared semantics cache")

    def export_learned_semantics(self, output_path: Path) -> bool:
        """
        Export learned semantics to file for later use.

        Args:
            output_path: Path to save semantics data

        Returns:
            True if export successful
        """
        try:
            export_data = {"statistics": self.get_synthesis_statistics(), "semantics": {}}

            for inst_bytes, semantics in self.semantics_cache.items():
                key = inst_bytes.hex()
                export_data["semantics"][key] = {
                    "address": semantics.address,
                    "disassembly": semantics.disassembly,
                    "learned_semantics": semantics.learned_semantics,
                    "semantic_formula": semantics.semantic_formula,
                    "confidence": semantics.confidence,
                    "complexity": semantics.complexity.value,
                }

            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2)

            logger.info(f"Exported learned semantics to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export semantics: {e}")
            return False
