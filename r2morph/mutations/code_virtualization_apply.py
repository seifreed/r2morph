"""Application orchestration for code virtualization."""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)


def apply_code_virtualization(pass_instance: Any, binary: Any) -> dict[str, Any]:
    """Apply code virtualization using the pass instance's transformation seams."""
    pass_instance._reset_random()
    pass_instance._ensure_analyzed(binary)
    logger.info("Applying code virtualization")

    virtualized, skipped, total_insns, total_bytecode = 0, 0, 0, 0
    unsupported: list[dict[str, Any]] = []
    partial: list[dict[str, Any]] = []
    unsupported_total = partial_total = 0

    for func in binary.get_functions():
        if virtualized >= pass_instance.max_functions:
            break
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue
        computed_jump = pass_instance._find_computed_jump(binary, func)
        if not pass_instance.virtualize_dispatch and computed_jump is not None:
            skipped += 1
            unsupported_total += 1
            pass_instance._record_diagnostic(
                unsupported,
                func,
                computed_jump,
                ("error", "computed_control_flow", "computed-jump virtualization is disabled"),
            )
            continue
        if random.random() > pass_instance.probability:
            skipped += 1
            continue

        region_result = pass_instance._virtualize_function(binary, func)
        if region_result is None and pass_instance.virtualize_dispatch:
            region_result = pass_instance._virtualize_dispatch_function(binary, func)
        if region_result is not None:
            total_insns += region_result["instructions"]
            total_bytecode += region_result["bytecode"]
            virtualized += 1
            continue

        unsupported_instruction = pass_instance._find_first_unvirtualizable_instruction(binary, func)
        if pass_instance.reject_partial_virtualization:
            skipped += 1
            unsupported_total += 1
            pass_instance._record_unsupported_function(
                unsupported,
                func,
                unsupported_instruction,
                "whole-function virtualization was not proven; partial virtualization is disabled: ",
            )
            continue

        result, partial_count = pass_instance._virtualize_fallback_run(binary, func, unsupported_instruction, partial)
        if result is not None:
            total_insns += result["instructions"]
            total_bytecode += result["bytecode"]
            virtualized += 1
            partial_total += partial_count
            continue
        unsupported_total += 1
        pass_instance._record_unsupported_function(unsupported, func, unsupported_instruction)

    return {
        "functions_virtualized": virtualized,
        "functions_skipped": skipped,
        "total_instructions": total_insns,
        "total_bytecode_bytes": total_bytecode,
        "unsupported_functions": unsupported,
        "unsupported_functions_total": unsupported_total,
        "partial_virtualization": partial,
        "partial_virtualization_total": partial_total,
    }
