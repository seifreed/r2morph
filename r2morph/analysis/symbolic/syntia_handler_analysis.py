"""VM handler analysis helpers for Syntia integration."""

from __future__ import annotations

import logging
from collections.abc import Callable

from r2morph.analysis.symbolic.syntia_analysis_helpers import (
    classify_handler_type,
    generate_equivalent_native_code,
    synthesize_handler_semantics,
)
from r2morph.analysis.symbolic.syntia_models import InstructionSemantics, VMHandlerSemantics

logger = logging.getLogger(__name__)


def analyze_vm_handler(
    handler_instructions: list[tuple[int, bytes, str]],
    handler_id: int,
    learn_instruction_semantics: Callable[[bytes, int, str], InstructionSemantics],
) -> VMHandlerSemantics:
    """Analyze a VM handler by learning per-instruction semantics and summarizing them."""
    logger.info(f"Analyzing VM handler {handler_id} with {len(handler_instructions)} instructions")

    handler_semantics = VMHandlerSemantics(
        handler_id=handler_id,
        entry_address=handler_instructions[0][0] if handler_instructions else 0,
        handler_type="unknown",
    )

    for address, inst_bytes, disasm in handler_instructions:
        semantics = learn_instruction_semantics(inst_bytes, address, disasm)
        handler_semantics.instruction_semantics.append(semantics)

    handler_semantics.overall_semantic_formula = synthesize_handler_semantics(handler_semantics.instruction_semantics)
    handler_semantics.handler_type = classify_handler_type(handler_semantics.instruction_semantics)

    if handler_semantics.instruction_semantics:
        confidences = [s.confidence for s in handler_semantics.instruction_semantics]
        handler_semantics.confidence = sum(confidences) / len(confidences)

    handler_semantics.equivalent_native_code = generate_equivalent_native_code(handler_semantics)
    return handler_semantics
