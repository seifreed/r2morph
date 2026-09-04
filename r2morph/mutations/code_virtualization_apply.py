"""Application orchestration for code virtualization."""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.analysis.exception_reader import ExceptionInfoReader
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)

_UNWIND_SECTION_NAMES = frozenset(
    {
        ".ARM.exidx",
        ".ARM.extab",
        ".gcc_except_table",
        ".pdata",
        ".xdata",
        "__unwind_info",
    }
)


def _unwind_metadata_name(binary: Any) -> str | None:
    """Return explicit exception-table metadata, failing closed on read errors.

    ELF ``.eh_frame`` and ``.eh_frame_hdr`` are also emitted for ordinary C
    functions and startup code, so their presence alone does not prove a
    language-level exception path. Parsed ELF frames are safe for the
    call-free, synchronous exception paths handled by the VM; incomplete
    exception metadata remains a conservative gate.
    """
    try:
        sections = binary.get_sections()
    except (OSError, RuntimeError, TypeError, ValueError):
        return "unavailable"

    for section in sections:
        raw_name = section.get("name", "")
        name = raw_name.rstrip("\x00") if isinstance(raw_name, str) else ""
        raw_size = section.get("size")
        if raw_size is not None:
            try:
                if int(raw_size) <= 0:
                    continue
            except (TypeError, ValueError):
                return "unavailable"
        if name in _UNWIND_SECTION_NAMES or name.endswith((".__gcc_except_tab", ".__unwind_info")):
            return name
    return None


def _transform_unsupported_function(
    pass_instance: Any,
    binary: Any,
    func: dict[str, Any],
    unsupported_instruction: dict[str, Any] | None,
    records: tuple[list[dict[str, Any]], list[dict[str, Any]]],
) -> dict[str, int]:
    """Handle a function rejected by the whole-function classifier."""
    unsupported, partial = records
    if pass_instance.reject_partial_virtualization:
        pass_instance._record_unsupported_function(
            unsupported,
            func,
            unsupported_instruction,
            "whole-function virtualization was not proven; partial virtualization is disabled: ",
        )
        return {"skipped": 1, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}
    result, partial_count = pass_instance._virtualize_fallback_run(binary, func, unsupported_instruction, partial)
    if result is not None:
        return {
            "skipped": 0,
            "unsupported": 0,
            "virtualized": 1,
            "instructions": result["instructions"],
            "bytecode": result["bytecode"],
            "partial": partial_count,
        }
    pass_instance._record_unsupported_function(unsupported, func, unsupported_instruction)
    return {"skipped": 0, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}


def _transform_dispatch_function(
    pass_instance: Any, binary: Any, func: dict[str, Any], unsupported: list[dict[str, Any]]
) -> dict[str, int]:
    """Transform a computed-dispatch function without falling back to a partial run."""
    region_result = pass_instance._virtualize_dispatch_function(binary, func)
    if region_result is not None:
        return {
            "skipped": 0,
            "unsupported": 0,
            "virtualized": 1,
            "instructions": region_result["instructions"],
            "bytecode": region_result["bytecode"],
            "partial": 0,
        }
    pass_instance._record_unsupported_function(
        unsupported,
        func,
        pass_instance._find_computed_jump(binary, func),
        "dispatch-region virtualization was not proven; ",
    )
    return {"skipped": 0, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}


def _transform_function(
    pass_instance: Any,
    binary: Any,
    func: dict[str, Any],
    records: tuple[list[dict[str, Any]], list[dict[str, Any]]],
    unwind_metadata: bool,
) -> dict[str, int]:
    """Transform one function after preflight checks have passed."""
    unsupported, partial = records
    if unwind_metadata:
        pass_instance._record_diagnostic(
            unsupported,
            func,
            None,
            (
                "error",
                "exceptions_and_unwinding",
                "unwind metadata could not be mapped to a complete function frame",
            ),
        )
        return {"skipped": 1, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}
    if pass_instance.virtualize_dispatch and pass_instance._has_computed_jump(binary, func):
        return _transform_dispatch_function(pass_instance, binary, func, unsupported)
    unsupported_instruction = pass_instance._find_first_unvirtualizable_instruction(binary, func)
    if unsupported_instruction is not None:
        return _transform_unsupported_function(pass_instance, binary, func, unsupported_instruction, records)

    region_result = pass_instance._virtualize_function(binary, func)
    if region_result is None:
        if pass_instance.reject_partial_virtualization:
            pass_instance._record_unsupported_function(
                unsupported,
                func,
                None,
                "whole-function virtualization was not proven; partial virtualization is disabled: ",
            )
            return {"skipped": 1, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}
        result, partial_count = pass_instance._virtualize_fallback_run(binary, func, None, partial)
    else:
        result, partial_count = region_result, 0
    if result is not None:
        return {
            "skipped": 0,
            "unsupported": 0,
            "virtualized": 1,
            "instructions": result["instructions"],
            "bytecode": result["bytecode"],
            "partial": partial_count,
        }
    pass_instance._record_unsupported_function(unsupported, func, None)
    return {"skipped": 0, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}


def _function_has_unproven_unwind_metadata(
    unwind_section: str | None,
    function_address: int,
    exception_frames: dict[int, Any] | None,
) -> bool:
    """Return whether unwind safety for a function remains unproven.

    The VM trampoline returns to the original function before any subsequent
    call can throw, and the run decoder excludes calls and control flow. A
    parsed ELF frame therefore remains valid for synchronous exception paths,
    including frames with landing pads. An unavailable parser result still
    fails closed because the function's unwind contract is unknown.
    """
    if unwind_section is None:
        return False
    if exception_frames is None:
        return True
    frame = exception_frames.get(function_address)
    if frame is None:
        frame = next(
            (
                candidate
                for candidate in exception_frames.values()
                if candidate.function_start <= function_address < candidate.function_end
            ),
            None,
        )
    return frame is None


def apply_code_virtualization(pass_instance: Any, binary: Any) -> dict[str, Any]:
    """Apply code virtualization using the pass instance's transformation seams."""
    pass_instance._reset_random()
    pass_instance._ensure_analyzed(binary)
    logger.info("Applying code virtualization")

    virtualized, skipped, total_insns, total_bytecode = 0, 0, 0, 0
    unsupported: list[dict[str, Any]] = []
    partial: list[dict[str, Any]] = []
    unsupported_total = partial_total = 0
    unwind_section = _unwind_metadata_name(binary)
    exception_frames: dict[int, Any] | None = None
    if unwind_section is not None and unwind_section != "unavailable":
        arch_info = binary.get_arch_info()
        if str(arch_info.get("format", "")).startswith("ELF"):
            exception_frames = ExceptionInfoReader(binary).read_exception_frames()

    for func in binary.get_functions():
        if virtualized >= pass_instance.max_functions:
            break
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue
        if unwind_section == "unavailable":
            skipped += 1
            unsupported_total += 1
            pass_instance._record_diagnostic(
                unsupported,
                func,
                None,
                (
                    "error",
                    "exceptions_and_unwinding",
                    "exception/unwinding metadata is present but VM preservation is not proven " f"({unwind_section})",
                ),
            )
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

        outcome = _transform_function(
            pass_instance,
            binary,
            func,
            (unsupported, partial),
            unwind_metadata=_function_has_unproven_unwind_metadata(
                unwind_section,
                int(func["addr"]),
                exception_frames,
            ),
        )
        skipped += outcome["skipped"]
        unsupported_total += outcome["unsupported"]
        virtualized += outcome["virtualized"]
        total_insns += outcome["instructions"]
        total_bytecode += outcome["bytecode"]
        partial_total += outcome["partial"]

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
