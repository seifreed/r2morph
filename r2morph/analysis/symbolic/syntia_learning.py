"""Instruction-learning helpers for Syntia integration."""

from __future__ import annotations

import logging
import time
from typing import Any

from r2morph.analysis.symbolic.syntia_models import InstructionSemantics

logger = logging.getLogger(__name__)


def learn_instruction_semantics(
    framework: Any,
    instruction_bytes: bytes,
    address: int,
    disassembly: str,
) -> InstructionSemantics:
    """Learn semantics for a single instruction using framework state."""
    start_time = time.time()

    if instruction_bytes in framework.semantics_cache:
        framework.synthesis_stats["cache_hits"] += 1
        cached = framework.semantics_cache[instruction_bytes]
        logger.debug(f"Cache hit for instruction at 0x{address:x}")
        return cached

    framework.synthesis_stats["instructions_analyzed"] += 1
    semantics = InstructionSemantics(address=address, instruction_bytes=instruction_bytes, disassembly=disassembly)

    try:
        fallback_result = framework._fallback_semantic_analysis(instruction_bytes, disassembly)
        semantics.learned_semantics = fallback_result["semantics"]
        semantics.confidence = fallback_result["confidence"]
    except Exception as e:
        logger.error(f"Error learning instruction semantics: {e}")
        framework.synthesis_stats["synthesis_failures"] += 1

    semantics.learning_time = time.time() - start_time
    semantics.complexity = framework._assess_semantic_complexity(semantics)
    framework.semantics_cache[instruction_bytes] = semantics
    return semantics
