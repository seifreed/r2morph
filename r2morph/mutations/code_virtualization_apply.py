"""Application orchestration for code virtualization."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import r2morph.core.randomness as random
from r2morph.analysis.cfg import CFGBuilder
from r2morph.analysis.defuse import DefUseAnalyzer
from r2morph.analysis.exception_reader import ExceptionInfoReader
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.core.support import _normalize_architecture_name

logger = logging.getLogger(__name__)

_UNWIND_SECTION_NAMES = frozenset(
    {
        ".ARM.exidx",
        ".ARM.extab",
        ".eh_frame",
        ".gcc_except_table",
        ".pdata",
        ".xdata",
        "__unwind_info",
    }
)


@dataclass(frozen=True, slots=True)
class _UnwindContext:
    """Preflight result passed to one complete-region transformation."""

    unproven: bool
    frame: Any | None


def _normalise_loader_format(raw_format: object) -> str:
    lowered = str(raw_format).strip().lower()
    if lowered.startswith("elf"):
        return "ELF"
    if lowered.startswith("pe"):
        return "PE"
    if "mach" in lowered:
        return "Mach-O"
    return str(raw_format).strip() or "unknown"


def _target_diagnostic(pass_instance: Any, binary: Any) -> dict[str, Any] | None:
    try:
        arch_info = binary.get_arch_info()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        arch_info = {}
    bits = arch_info.get("bits")
    try:
        normalized_bits = int(bits)
    except (TypeError, ValueError):
        normalized_bits = None
    target_format = _normalise_loader_format(arch_info.get("format", "unknown"))
    target_arch = _normalize_architecture_name(arch_info.get("arch", "unknown"), normalized_bits)
    support = pass_instance.get_support()
    if target_format in support.formats and target_arch in support.architectures:
        return None
    return {
        "format": target_format,
        "architecture": target_arch,
        "bits": normalized_bits,
        "supported_formats": list(support.formats),
        "supported_architectures": list(support.architectures),
        "reason": "target is outside the code virtualization support envelope",
    }


def _empty_result(target_diagnostic: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "functions_virtualized": 0,
        "functions_skipped": 0,
        "total_instructions": 0,
        "total_bytecode_bytes": 0,
        "unsupported_functions": [],
        "unsupported_functions_total": 0,
        "unsupported_function_capabilities": {},
        "unsupported_function_severities": {},
        "partial_virtualization": [],
        "partial_virtualization_total": 0,
        "partial_virtualization_capabilities": {},
        "partial_virtualization_severities": {},
        "target_diagnostic": target_diagnostic,
    }


def _field_counts(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        value = record.get(field)
        if isinstance(value, str) and value:
            counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _executable_ranges(binary: Any) -> tuple[tuple[int, int], ...]:
    """Return trustworthy virtual ranges for executable sections."""
    try:
        sections = binary.get_sections()
        ranges = []
        for section in sections:
            if "x" not in str(section.get("perm", "")):
                continue
            start = int(section.get("vaddr", 0))
            size = int(section.get("vsize", section.get("size", 0)))
            if start >= 0 and size > 0:
                ranges.append((start, size))
        return tuple(ranges)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return ()


def _address_in_ranges(address: object, ranges: Iterable[tuple[int, int]]) -> bool:
    return isinstance(address, int) and any(start <= address < start + size for start, size in ranges)


def _unwind_metadata_name(binary: Any) -> str | None:
    """Return explicit exception-table metadata, failing closed on read errors.

    ELF ``.eh_frame`` is the unwind contract for ordinary functions; a parsed
    frame is required before a VM blob can be published for that function.
    Language-level LSDA call sites remain subject to the same call-free gate.
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


def _read_exception_frames(binary: Any, unwind_section: str | None) -> dict[int, Any] | None:
    """Parse unwind frames for every format recognized by the reader."""
    if unwind_section is None or unwind_section == "unavailable":
        return None
    try:
        return ExceptionInfoReader(binary).read_exception_frames()
    except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.debug("Failed to read exception frames: %s", exc)
        return None


def _transform_unsupported_function(
    pass_instance: Any,
    binary: Any,
    func: dict[str, Any],
    instruction_context: tuple[dict[str, Any] | None, Any | None],
    records: tuple[list[dict[str, Any]], list[dict[str, Any]]],
) -> dict[str, Any]:
    """Handle a function rejected by the whole-function classifier."""
    unsupported_instruction, unwind_frame = instruction_context
    unsupported, partial = records
    if unwind_frame is not None:
        pass_instance._record_diagnostic(
            unsupported,
            func,
            unsupported_instruction,
            (
                "error",
                "exceptions_and_unwinding",
                "partial virtualization has no unwind metadata for the injected VM run",
            ),
        )
        return {"skipped": 1, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}
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
            "body_ranges": result.get("body_ranges", ()),
        }
    pass_instance._record_unsupported_function(unsupported, func, unsupported_instruction)
    return {"skipped": 0, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}


def _transform_dispatch_function(
    pass_instance: Any,
    binary: Any,
    func: dict[str, Any],
    unsupported: list[dict[str, Any]],
    unwind_frame: Any | None,
) -> dict[str, Any]:
    """Transform a computed-dispatch function without falling back to a partial run."""
    region_result = pass_instance._virtualize_dispatch_function(binary, func, unwind_frame)
    if region_result is not None:
        return {
            "skipped": 0,
            "unsupported": 0,
            "virtualized": 1,
            "instructions": region_result["instructions"],
            "bytecode": region_result["bytecode"],
            "partial": 0,
            "body_ranges": region_result.get("body_ranges", ()),
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
    unwind: _UnwindContext,
) -> dict[str, Any]:
    """Transform one function after preflight checks have passed."""
    unsupported, partial = records
    cfg = CFGBuilder(binary).build_cfg(int(func["addr"]))
    if (unwind.unproven and unwind.frame is None) or not _static_dataflow_is_complete(cfg):
        capability = "exceptions_and_unwinding" if unwind.unproven else "static_dataflow"
        reason = (
            "unwind metadata could not be mapped to a complete function frame"
            if unwind.unproven
            else "CFG, liveness, and SSA coverage was not proven for the function"
        )
        pass_instance._record_diagnostic(
            unsupported,
            func,
            _unwind_blocking_instruction(unwind.frame, int(func["addr"])),
            ("error", capability, reason),
        )
        return {"skipped": 1, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}
    if pass_instance.virtualize_dispatch and pass_instance._has_computed_jump(binary, func):
        return _transform_dispatch_function(pass_instance, binary, func, unsupported, unwind.frame)
    unsupported_instruction = pass_instance._find_first_unvirtualizable_instruction(binary, func)
    if unsupported_instruction is not None:
        return _transform_unsupported_function(
            pass_instance,
            binary,
            func,
            (unsupported_instruction, unwind.frame),
            records,
        )

    region_result = pass_instance._virtualize_function(binary, func, unwind.frame)
    if region_result is None:
        if unwind.unproven:
            pass_instance._record_diagnostic(
                unsupported,
                func,
                _unwind_blocking_instruction(unwind.frame, int(func["addr"])),
                (
                    "error",
                    "exceptions_and_unwinding",
                    "LSDA or landing-pad ranges overlap the candidate VM region",
                ),
            )
            skipped_count = 1
            partial_count = 0
            result = None
        elif pass_instance.reject_partial_virtualization:
            pass_instance._record_unsupported_function(
                unsupported,
                func,
                None,
                "whole-function virtualization was not proven; partial virtualization is disabled: ",
            )
            skipped_count = 1
            partial_count = 0
            result = None
        else:
            result, partial_count = pass_instance._virtualize_fallback_run(binary, func, None, partial)
            skipped_count = 0
    else:
        result, partial_count, skipped_count = region_result, 0, 0
    if result is not None:
        return {
            "skipped": 0,
            "unsupported": 0,
            "virtualized": 1,
            "instructions": result["instructions"],
            "bytecode": result["bytecode"],
            "partial": partial_count,
            "body_ranges": result.get("body_ranges", ()),
        }
    pass_instance._record_unsupported_function(unsupported, func, None)
    return {
        "skipped": skipped_count,
        "unsupported": 1,
        "virtualized": 0,
        "instructions": 0,
        "bytecode": 0,
        "partial": 0,
    }


def _function_has_unproven_unwind_metadata(
    unwind_section: str | None,
    function_address: int,
    exception_frames: dict[int, Any] | None,
) -> bool:
    """Return whether unwind safety for a function remains unproven.

    The VM metadata writer covers ordinary FDEs only. An LSDA or landing pad
    also requires remapping protected ranges and preserving handler bodies;
    reject it even when the candidate-region call detector did not find a call.
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
    if frame is None:
        # A linked ELF may carry .eh_frame entries for startup/runtime code
        # while a target function intentionally has no unwind contract.
        return unwind_section != ".eh_frame"
    return frame.lsda_address is not None or bool(frame.landing_pads)


def _exception_frame_for_function(function_address: int, exception_frames: dict[int, Any] | None) -> Any | None:
    """Return the parsed frame containing a function address, if available."""
    if exception_frames is None:
        return None
    frame = exception_frames.get(function_address)
    if frame is not None:
        return frame
    return next(
        (
            candidate
            for candidate in exception_frames.values()
            if candidate.function_start <= function_address < candidate.function_end
        ),
        None,
    )


def _unwind_blocking_instruction(frame: Any | None, function_address: int) -> dict[str, int]:
    """Return the most specific native address responsible for an unwind gate."""
    if frame is None:
        return {"addr": function_address}
    for pad in frame.landing_pads:
        call_site_start = pad.metadata.get("call_site_start")
        if isinstance(call_site_start, int):
            return {"addr": call_site_start}
        if isinstance(pad.address, int):
            return {"addr": pad.address}
    return {"addr": function_address}


def _static_dataflow_is_complete(cfg: Any) -> bool:
    """Require CFG, liveness, and SSA coverage before lowering a function."""
    try:
        if not cfg.blocks:
            return False
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()
        ssa_blocks = analyzer.build_ssa_form()
    except (AttributeError, OSError, BrokenPipeError, RuntimeError, TypeError, ValueError) as exc:
        logger.debug("Static dataflow failed: %s", exc)
        return False
    return set(ssa_blocks) == set(cfg.blocks) and analyzer.has_complete_liveness_coverage()


def apply_code_virtualization(pass_instance: Any, binary: Any) -> dict[str, Any]:
    """Apply code virtualization using the pass instance's transformation seams."""
    pass_instance._reset_random()
    target_diagnostic = _target_diagnostic(pass_instance, binary)
    if target_diagnostic is not None:
        logger.warning("Skipping code virtualization for unsupported target: %s", target_diagnostic)
        return _empty_result(target_diagnostic)
    pass_instance._ensure_analyzed(binary)
    logger.info("Applying code virtualization")

    virtualized, skipped, total_insns, total_bytecode = 0, 0, 0, 0
    unsupported: list[dict[str, Any]] = []
    partial: list[dict[str, Any]] = []
    covered_ranges: list[tuple[int, int]] = []
    unsupported_total = partial_total = 0
    executable_ranges = _executable_ranges(binary)
    unwind_section = _unwind_metadata_name(binary)
    exception_frames = _read_exception_frames(binary, unwind_section)

    for func in binary.get_functions():
        if virtualized >= pass_instance.max_functions:
            break
        function_address = func.get("addr")
        if executable_ranges and not _address_in_ranges(function_address, executable_ranges):
            continue
        if _address_in_ranges(function_address, covered_ranges):
            continue
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
            unwind=_UnwindContext(
                _function_has_unproven_unwind_metadata(
                    unwind_section,
                    int(func["addr"]),
                    exception_frames,
                ),
                _exception_frame_for_function(int(func["addr"]), exception_frames),
            ),
        )
        skipped += outcome["skipped"]
        unsupported_total += outcome["unsupported"]
        virtualized += outcome["virtualized"]
        total_insns += outcome["instructions"]
        total_bytecode += outcome["bytecode"]
        partial_total += outcome["partial"]
        covered_ranges.extend(outcome.get("body_ranges", ()))

    return {
        "functions_virtualized": virtualized,
        "functions_skipped": skipped,
        "total_instructions": total_insns,
        "total_bytecode_bytes": total_bytecode,
        "unsupported_functions": unsupported,
        "unsupported_functions_total": unsupported_total,
        "unsupported_function_capabilities": _field_counts(unsupported, "capability"),
        "unsupported_function_severities": _field_counts(unsupported, "severity"),
        "partial_virtualization": partial,
        "partial_virtualization_total": partial_total,
        "partial_virtualization_capabilities": _field_counts(partial, "capability"),
        "partial_virtualization_severities": _field_counts(partial, "severity"),
        "target_diagnostic": None,
    }
