"""Pure analysis helpers for Syntia framework integration."""

from __future__ import annotations

from typing import Any

from .syntia_models import InstructionSemantics, SemanticComplexity, VMHandlerSemantics


def fallback_semantic_analysis(disassembly: str) -> dict[str, Any]:
    """Fallback semantic analysis when Syntia is not available."""
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


def assess_semantic_complexity(semantics: InstructionSemantics) -> SemanticComplexity:
    """Assess the complexity of learned semantics."""
    if not semantics.learned_semantics:
        return SemanticComplexity.UNKNOWN

    semantic_str = semantics.learned_semantics.lower()

    if len(semantic_str) < 50 and semantics.confidence > 0.8:
        return SemanticComplexity.SIMPLE
    if len(semantic_str) < 200 and semantics.confidence > 0.5:
        return SemanticComplexity.MEDIUM
    return SemanticComplexity.COMPLEX


def synthesize_handler_semantics(instruction_semantics: list[InstructionSemantics]) -> str | None:
    """Synthesize overall semantics for a VM handler from individual instructions."""
    if not instruction_semantics:
        return None

    semantic_parts = []
    for sem in instruction_semantics:
        if sem.learned_semantics and sem.confidence > 0.5:
            semantic_parts.append(sem.learned_semantics)

    if semantic_parts:
        return " -> ".join(semantic_parts)

    return None


def classify_handler_type(instruction_semantics: list[InstructionSemantics]) -> str:
    """Classify VM handler type based on instruction semantics."""
    if not instruction_semantics:
        return "unknown"

    semantic_text = " ".join(sem.learned_semantics or "" for sem in instruction_semantics if sem.learned_semantics).lower()

    if any(keyword in semantic_text for keyword in ["add", "sub", "mul", "div", "arithmetic"]):
        return "arithmetic"
    if any(keyword in semantic_text for keyword in ["jmp", "branch", "control", "conditional"]):
        return "branch"
    if any(keyword in semantic_text for keyword in ["mov", "load", "store", "memory"]):
        return "memory"
    if any(keyword in semantic_text for keyword in ["push", "pop", "stack"]):
        return "stack"
    return "unknown"


def generate_equivalent_native_code(handler_semantics: VMHandlerSemantics) -> str | None:
    """Generate equivalent native code for a VM handler."""
    if not handler_semantics.overall_semantic_formula:
        return None

    if handler_semantics.handler_type == "arithmetic":
        if "add" in handler_semantics.overall_semantic_formula.lower():
            return "add eax, ebx"
        if "sub" in handler_semantics.overall_semantic_formula.lower():
            return "sub eax, ebx"
    elif handler_semantics.handler_type == "memory":
        return "mov eax, [ebx]"
    elif handler_semantics.handler_type == "branch":
        return "cmp eax, ebx\nje target"

    return f"; Equivalent code for {handler_semantics.handler_type} handler"
