"""Application orchestration for code virtualization."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import capstone

import r2morph.core.randomness as random
from r2morph.analysis.call_graph_parsing import extract_call_target
from r2morph.analysis.cfg import CFGBuilder
from r2morph.analysis.defuse import DefUseAnalyzer
from r2morph.analysis.exception_models import ExceptionFrame
from r2morph.analysis.exception_reader import ExceptionInfoReader
from r2morph.core.constants import MAX_FUNCTION_ANALYSIS_COUNT, MINIMUM_FUNCTION_SIZE
from r2morph.core.support import _normalize_architecture_name
from r2morph.mutations import code_virtualization_region_classification as classification

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
_DEFAULT_MAX_FUNCTION_SIZE = 64 * 1024
_MAX_COMPACT_RET_SCAN = 128
_MAX_ENTRYPOINT_PROLOGUE_BYTES = 4
# ponytail: bounded local target cluster; replace with linker provenance if wider layouts matter.
_MAX_APPLICATION_ENTRY_SCAN_INSNS = 256
_MAX_APPLICATION_TARGET_GAP = 0x2000
_LARGE_APPLICATION_POPULATION = 1024
_TERMINAL_SYSTEM_CALL_TYPES = frozenset({"syscall", "swi"})
_APPLICATION_BRANCH_TYPES = frozenset({"call", "jmp", "cjmp", "jrcxz"})
_INTERNAL_SYMBOL_MARKERS = (".cold", ".constprop", ".isra", ".part")
_RUNTIME_INITIALIZATION_NAMES = frozenset(
    {
        "sym._init",
        "sym._fini",
        "sym._dl_relocate_static_pie",
        "sym.register_tm_clones",
        "sym.deregister_tm_clones",
        "sym.frame_dummy",
        "entry.init0",
        "entry.fini0",
    }
)


def _is_runtime_entrypoint(
    function: dict[str, Any],
    unwind_section: str | None,
    entrypoint_addresses: frozenset[int] = frozenset(),
) -> bool:
    """Exclude a compiler-generated loader entry stub from VM candidates."""
    name = str(function.get("name", "")).strip()
    address = function.get("addr")
    entrypoint_nearby = isinstance(address, int) and any(
        0 <= address - entrypoint <= _MAX_ENTRYPOINT_PROLOGUE_BYTES for entrypoint in entrypoint_addresses
    )
    return (
        name in _RUNTIME_INITIALIZATION_NAMES
        or "__libc_start_main" in name
        or entrypoint_nearby
        or (unwind_section == ".eh_frame" and (name == "entry0" or name.startswith("entry.")))
    )


def _function_order_key(function: dict[str, Any]) -> tuple[int, int]:
    """Prefer named application symbols while retaining deterministic ordering."""
    name = str(function.get("name", "")).strip().lower()
    named_application = name in {"main", "_main", "sym.main"} or (
        name.startswith("sym.")
        and not name.startswith(("sym._", "sym.__"))
        and not any(marker in name for marker in _INTERNAL_SYMBOL_MARKERS)
    )
    address = function.get("addr")
    return (0 if named_application else 1, int(address) if isinstance(address, int) else 0)


def _direct_branch_targets(disassembly: object, stop_on_unconditional_jump: bool = False) -> frozenset[int]:
    instructions = disassembly.get("ops", []) if isinstance(disassembly, dict) else disassembly
    if not isinstance(instructions, list):
        return frozenset()
    targets: set[int] = set()
    for instruction in instructions:
        if not isinstance(instruction, dict) or instruction.get("type") not in _APPLICATION_BRANCH_TYPES:
            continue
        target = instruction.get("jump")
        if isinstance(target, int):
            targets.add(target)
        if stop_on_unconditional_jump and instruction.get("type") == "jmp":
            break
    return frozenset(targets)


def _has_direct_call_to_multi_return_function(
    binary: Any,
    function: dict[str, Any],
    known_function_addresses: frozenset[int],
) -> bool:
    """Recognize an entry wrapper that delegates to a multi-return function."""
    try:
        disassembly = binary.r2.cmdj(f"pdfj @ {function['addr']}") or {}
    except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError):
        return False
    instructions = disassembly.get("ops", []) if isinstance(disassembly, dict) else []
    call_targets = {
        instruction["jump"]
        for instruction in instructions
        if (
            isinstance(instruction, dict)
            and instruction.get("type") in {"call", "rcall"}
            and isinstance(instruction.get("jump"), int)
            and instruction["jump"] in known_function_addresses
            and instruction["jump"] != function.get("addr")
        )
    }
    for target in call_targets:
        try:
            target_disassembly = binary.r2.cmdj(f"pdfj @ {target}") or {}
        except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError):
            continue
        target_instructions = target_disassembly.get("ops", []) if isinstance(target_disassembly, dict) else []
        return_count = sum(
            isinstance(instruction, dict)
            and (
                instruction.get("type") in {"ret", "retn"}
                or str(instruction.get("opcode", "")).split(maxsplit=1)[0].lower() in {"ret", "retn"}
            )
            for instruction in target_instructions
        )
        if return_count > 1:
            return True
    return False


def _dispatch_entrypoint_addresses(pass_instance: Any, binary: Any) -> frozenset[int]:
    """Keep only standalone or computed-jump loader entries in the VM set."""
    functions = binary.get_functions()
    known_function_addresses = frozenset(
        int(function["addr"]) for function in functions if isinstance(function.get("addr"), int)
    )
    entrypoint_addresses = _entrypoint_addresses(binary)
    return frozenset(
        int(function["addr"])
        for function in functions
        if (
            isinstance(function.get("addr"), int)
            and function["addr"] in entrypoint_addresses
            and (
                pass_instance._has_computed_jump(binary, function)
                or (
                    _has_terminal_system_call(binary, function)
                    and not _has_direct_call_to_multi_return_function(binary, function, known_function_addresses)
                )
            )
        )
    )


def _application_target_addresses(binary: Any, functions: list[dict[str, Any]]) -> frozenset[int]:
    """Prefer direct targets from the application's conventional entry symbol."""
    entry_functions = [
        function
        for function in functions
        if str(function.get("name", "")).strip().lower() in {"main", "_main", "sym.main"}
    ]
    targets: set[int] = set()
    for function in entry_functions:
        address = function.get("addr")
        if not isinstance(address, int):
            continue
        commands = (f"pdfj @ {address}", f"pdj {_MAX_APPLICATION_ENTRY_SCAN_INSNS} @ {address}")
        for command in commands:
            try:
                disassembly = binary.r2.cmdj(command) or []
            except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError):
                continue
            branch_targets = _direct_branch_targets(disassembly, command.startswith("pdj"))
            if branch_targets:
                targets.update(branch_targets)
                break
    for target in tuple(sorted(targets)):
        target_function = next((function for function in functions if function.get("addr") == target), None)
        if (
            not target_function
            or not isinstance(target_function.get("size"), int)
            or target_function["size"] >= MINIMUM_FUNCTION_SIZE
        ):
            continue
        try:
            wrapper = binary.r2.cmdj(f"pdfj @ {target}") or {}
        except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError):
            continue
        targets.update(_direct_branch_targets(wrapper))
    return frozenset(targets)


def _application_candidate_addresses(
    functions: list[dict[str, Any]], target_addresses: frozenset[int]
) -> frozenset[int]:
    """Keep the first local target cluster after the application entry."""
    entry_addresses = sorted(
        int(function["addr"])
        for function in functions
        if str(function.get("name", "")).strip().lower() in {"main", "_main", "sym.main"}
        and isinstance(function.get("addr"), int)
    )
    if not entry_addresses:
        return target_addresses
    entry_ranges = tuple(
        (
            int(function.get("minaddr", function["addr"])),
            int(function.get("maxaddr", function["addr"] + int(function.get("size", 0) or 0) - 1))
            - int(function.get("minaddr", function["addr"]))
            + 1,
        )
        for function in functions
        if str(function.get("name", "")).strip().lower() in {"main", "_main", "sym.main"}
        and isinstance(function.get("addr"), int)
    )
    forward_targets = sorted(
        target
        for target in target_addresses
        if target >= entry_addresses[0] and not _address_in_ranges(target, entry_ranges)
    )
    if not forward_targets:
        return frozenset()
    cluster = [forward_targets[0]]
    for target in forward_targets[1:]:
        if target - cluster[-1] > _MAX_APPLICATION_TARGET_GAP:
            break
        cluster.append(target)
    return frozenset(cluster)


def _application_target_functions(
    binary: Any,
    functions: list[dict[str, Any]],
    target_addresses: frozenset[int],
) -> list[dict[str, Any]]:
    """Recover exact target functions that analysis did not enumerate."""
    known_addresses = {function.get("addr") for function in functions}
    additions: list[dict[str, Any]] = []
    for address in sorted(target_addresses):
        if address in known_addresses:
            continue
        try:
            binary.r2.cmd(f"af @ {address}")
            candidates = binary.r2.cmdj(f"afij @ {address}") or []
        except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError):
            continue
        candidate = next(
            (
                function
                for function in candidates
                if isinstance(function, dict)
                and function.get("addr") == address
                and isinstance(function.get("size"), int)
                and function["size"] > 0
            ),
            None,
        )
        if candidate is not None:
            additions.append(candidate)
            known_addresses.add(address)
    return functions + additions


def _is_unreferenced_function_chunk(binary: Any, function: dict[str, Any], functions: list[dict[str, Any]]) -> bool:
    """Exclude r2 auto-functions that are unreferenced tails of a prior function."""
    name = str(function.get("name", "")).strip()
    address = function.get("addr")
    if not name.startswith("fcn.") or not isinstance(address, int):
        return False
    predecessor = next(
        (
            candidate
            for candidate in functions
            if isinstance(candidate.get("addr"), int)
            and isinstance(candidate.get("size"), int)
            and candidate["addr"] + candidate["size"] == address
        ),
        None,
    )
    if predecessor is None:
        return False
    try:
        xrefs = binary.get_xrefs_to(address)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return False
    return not any(str(xref.get("type", "")).upper() in {"CALL", "CODE", "JUMP"} for xref in xrefs)


@dataclass(frozen=True, slots=True)
class _UnwindContext:
    """Preflight result passed to one complete-region transformation."""

    unproven: bool
    frame: Any | None
    reason: str | None = None
    blocking_instruction: dict[str, Any] | None = None


def _has_language_unwind_contract(frame: Any | None) -> bool:
    """Return whether a frame carries language-level exception metadata."""
    return frame is not None and (
        getattr(frame, "lsda_address", None) is not None or bool(getattr(frame, "landing_pads", ()))
    )


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


def _analysis_budget_result(analysis_budget: int) -> dict[str, Any]:
    """Reject oversized function populations before expensive per-function analysis."""
    capability = "analysis_budget"
    result = _empty_result(None)
    result.update(
        {
            "functions_skipped": analysis_budget + 1,
            "unsupported_functions": [
                {
                    "function_address": 0,
                    "capability": capability,
                    "severity": "error",
                    "reason": "function population exceeds the VM analysis budget",
                }
            ],
            "unsupported_functions_total": 1,
            "unsupported_function_capabilities": {capability: 1},
            "unsupported_function_severities": {"error": 1},
        }
    )
    return result


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


def _plt_ranges(binary: Any) -> tuple[tuple[int, int], ...]:
    """Return linker-stub ranges so external thunks are not VM candidates."""
    try:
        sections = binary.get_sections()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return ()
    ranges: list[tuple[int, int]] = []
    for section in sections:
        name = str(section.get("name", "")).lower()
        if ".plt" not in name:
            continue
        permissions = section.get("perm")
        if permissions is not None and "x" not in str(permissions):
            continue
        try:
            start = int(section.get("vaddr", section.get("addr", section.get("virtual_address", 0))))
        except (TypeError, ValueError):
            continue
        size = 0
        for key in ("vsize", "size", "virtual_size"):
            try:
                candidate = int(section.get(key, 0))
            except (TypeError, ValueError):
                continue
            size = max(size, candidate)
        if start >= 0 and size > 0:
            ranges.append((start, size))
    return tuple(ranges)


def _entrypoint_addresses(binary: Any) -> frozenset[int]:
    """Return loader entry addresses when the binary adapter exposes them."""
    try:
        entries = binary.r2.cmdj("iej") or []
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return frozenset()
    return frozenset(
        int(entry["vaddr"]) for entry in entries if isinstance(entry, dict) and isinstance(entry.get("vaddr"), int)
    )


def _runtime_initialization_addresses(binary: Any) -> frozenset[int]:
    """Resolve linker helper aliases that the function list may leave anonymous."""
    try:
        flags = binary.r2.cmdj("fj") or []
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return frozenset()
    addresses: set[int] = set()
    for flag in flags:
        if not isinstance(flag, dict):
            continue
        names = {str(flag.get("name", "")), f"sym.{flag.get('realname', '')}"}
        if not names & _RUNTIME_INITIALIZATION_NAMES:
            continue
        address = flag.get("addr")
        if isinstance(address, int):
            addresses.add(address)
    return frozenset(addresses)


def _has_terminal_system_call(binary: Any, function: dict[str, Any]) -> bool:
    """Recognize user entrypoints that terminate through the native syscall ABI."""
    try:
        disassembly = binary.r2.cmdj(f"pdfj @ {function['addr']}") or {}
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return False
    if not isinstance(disassembly, dict):
        return False
    return any(
        instruction.get("type") in _TERMINAL_SYSTEM_CALL_TYPES
        or str(instruction.get("opcode", "")).strip().lower().split(maxsplit=1)[0] in _TERMINAL_SYSTEM_CALL_TYPES
        for instruction in disassembly.get("ops", [])
        if isinstance(instruction, dict)
    )


def _address_in_ranges(address: object, ranges: Iterable[tuple[int, int]]) -> bool:
    return isinstance(address, int) and any(start <= address < start + size for start, size in ranges)


def _exceeds_function_size_budget(function: dict[str, Any], maximum_size: int) -> bool:
    size = function.get("size")
    return isinstance(size, int) and size > maximum_size


def _skip_oversized_function(
    pass_instance: Any,
    function: dict[str, Any],
    unsupported: list[dict[str, Any]],
    skipped: int,
    unsupported_total: int,
) -> tuple[int, int]:
    pass_instance._record_diagnostic(
        unsupported,
        function,
        None,
        ("error", "analysis_budget", "function exceeds the configured static-analysis size budget"),
    )
    return skipped + 1, unsupported_total + 1


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


def _read_exception_frames(binary: Any, unwind_section: str | None) -> tuple[dict[int, Any] | None, str | None]:
    """Parse unwind frames and preserve parser failures for fail-closed preflight."""
    if unwind_section is None or unwind_section == "unavailable":
        return None, None
    try:
        reader = ExceptionInfoReader(binary)
        frames = reader.read_exception_frames()
        return frames, reader.read_error
    except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.debug("Failed to read exception frames: %s", exc)
        return None, f"failed to read {unwind_section} metadata"


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


def _preflight_rejection_diagnostic(unwind: _UnwindContext) -> tuple[str, str]:
    if unwind.unproven:
        return (
            "exceptions_and_unwinding",
            unwind.reason or "unwind metadata could not be mapped to a complete function frame",
        )
    return "ssa_liveness", "CFG, liveness, and SSA coverage was not proven for the function"


def _preflight_function(
    pass_instance: Any,
    binary: Any,
    func: dict[str, Any],
    unwind: _UnwindContext,
) -> tuple[str, dict[str, Any] | None]:
    """Classify a function before running expensive CFG and dataflow analysis."""
    if unwind.unproven and (unwind.frame is None or unwind.reason is not None):
        return "reject", None
    if pass_instance.virtualize_dispatch and pass_instance._has_computed_jump(binary, func):
        return "dispatch", None
    unsupported_instruction = pass_instance._find_first_unvirtualizable_instruction(binary, func)
    if unsupported_instruction is not None:
        return "unsupported", unsupported_instruction
    cfg = CFGBuilder(binary).build_cfg(int(func["addr"]))
    if not _static_dataflow_is_complete(cfg) and not _has_language_unwind_contract(unwind.frame):
        return "reject", None
    return "transform", None


def _transform_function(
    pass_instance: Any,
    binary: Any,
    func: dict[str, Any],
    records: tuple[list[dict[str, Any]], list[dict[str, Any]]],
    unwind: _UnwindContext,
) -> dict[str, Any]:
    """Transform one function after preflight checks have passed."""
    unsupported, partial = records
    if _has_materialized_instructions(binary, func) is False:
        return {"skipped": 1, "unsupported": 0, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}
    preflight_status, unsupported_instruction = _preflight_function(pass_instance, binary, func, unwind)
    if preflight_status == "dispatch":
        return _transform_dispatch_function(pass_instance, binary, func, unsupported, unwind.frame)
    if preflight_status == "unsupported":
        return _transform_unsupported_function(
            pass_instance,
            binary,
            func,
            (unsupported_instruction, unwind.frame),
            records,
        )
    if preflight_status == "reject":
        capability, reason = _preflight_rejection_diagnostic(unwind)
        pass_instance._record_diagnostic(
            unsupported,
            func,
            unwind.blocking_instruction or _unwind_blocking_instruction(unwind.frame, int(func["addr"])),
            ("error", capability, reason),
        )
        return {"skipped": 1, "unsupported": 1, "virtualized": 0, "instructions": 0, "bytecode": 0, "partial": 0}

    region_result = pass_instance._virtualize_function(binary, func, unwind.frame)
    if region_result is None:
        if unwind.unproven or _has_language_unwind_contract(unwind.frame):
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
            return {
                "skipped": 1,
                "unsupported": 1,
                "virtualized": 0,
                "instructions": 0,
                "bytecode": 0,
                "partial": 0,
            }
        else:
            result, partial_count = pass_instance._virtualize_fallback_run(binary, func, None, partial)
            skipped_count = 0
    else:
        result, partial_count, skipped_count = region_result, 0, 0
    if result is None:
        pass_instance._record_unsupported_function(unsupported, func, None)
        outcome = {
            "skipped": skipped_count,
            "unsupported": 1,
            "virtualized": 0,
            "instructions": 0,
            "bytecode": 0,
            "partial": 0,
        }
    else:
        outcome = {
            "skipped": 0,
            "unsupported": 0,
            "virtualized": 1,
            "instructions": result["instructions"],
            "bytecode": result["bytecode"],
            "partial": partial_count,
            "body_ranges": result.get("body_ranges", ()),
        }
    return outcome


def _function_has_unproven_unwind_metadata(
    unwind_section: str | None,
    function_address: int,
    exception_frames: dict[int, Any] | None,
    has_native_call: bool = False,
    ordinary_frame_available: bool = False,
) -> bool:
    """Return whether unwind safety for a function remains unproven.

    LSDA-bearing regions are safe only after the parsed template and personality
    are available. Region construction then verifies protected ranges and
    remaps them into the injected VM metadata.
    """
    if unwind_section is None:
        return False
    if exception_frames is None:
        return unwind_section != ".eh_frame" or has_native_call
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
        return not ordinary_frame_available and (unwind_section != ".eh_frame" or has_native_call)
    if frame.lsda_address is None and not frame.landing_pads:
        return False
    return frame.lsda_template is None or not isinstance(frame.personality, int)


def _function_has_native_call(binary: Any, function: dict[str, Any]) -> bool:
    """Return whether a candidate contains a native call needing unwind data."""
    try:
        instructions = binary.get_function_disasm(int(function["addr"]))
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return False
    return any(
        str(instruction.get("disasm") or instruction.get("opcode") or "").lower().startswith("call")
        for instruction in instructions
    )


def _unwind_contract_blocker(
    binary: Any, function: dict[str, Any], unwind_frame: Any | None
) -> tuple[dict[str, Any], str] | None:
    """Find ABI shapes whose native-call unwind contract is not proven."""
    if unwind_frame is None:
        return None
    try:
        instructions = binary.get_function_disasm(int(function["addr"]))
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return None
    if not any(
        str(instruction.get("disasm") or instruction.get("opcode") or "").lower().startswith("call")
        for instruction in instructions
    ):
        return None
    for instruction in instructions:
        opcode = str(instruction.get("disasm") or instruction.get("opcode") or "").lower()
        if _is_stack_guard_tls_access(opcode):
            return instruction, "native calls combined with TLS access have no proven VM unwind contract"
    return None


def _is_stack_guard_tls_access(opcode: str) -> bool:
    """Recognize ABI stack-canary loads without rejecting ordinary TLS variables."""
    for segment, offset in (("fs:", "0x28"), ("gs:", "0x14")):
        if segment not in opcode:
            continue
        operand = opcode.split(segment, 1)[1].lstrip(" [")
        if operand.split("]", 1)[0].split(",", 1)[0].strip() in {offset, f"+{offset}"}:
            return True
    return False


def _protected_callee_addresses(binary: Any, exception_frames: dict[int, Any] | None) -> frozenset[int]:
    """Find direct callees reached by LSDA-protected call sites."""
    if not exception_frames:
        return frozenset()
    protected_ranges = tuple(
        (site.start_address, site.end_address)
        for frame in exception_frames.values()
        for site in getattr(frame, "lsda_call_sites", ())
        if site.landing_pad or site.action_index
    )
    if not protected_ranges:
        return frozenset()
    try:
        functions = binary.get_functions()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return frozenset()
    protected_callees: set[int] = set()
    function_sizes = {
        function.get("addr"): function.get("size") for function in functions if isinstance(function.get("addr"), int)
    }
    for function in functions:
        function_address = function.get("addr")
        if not isinstance(function_address, int):
            continue
        try:
            instructions = binary.get_function_disasm(function_address)
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            continue
        for instruction in instructions:
            address = instruction.get("offset", instruction.get("addr"))
            if not isinstance(address, int) or not any(start <= address < end for start, end in protected_ranges):
                continue
            disassembly = str(instruction.get("disasm") or instruction.get("opcode") or "")
            if instruction.get("type") != "call" and not disassembly.lower().startswith("call"):
                continue
            target = instruction.get("jump")
            if not isinstance(target, int):
                target = extract_call_target(disassembly)
            if isinstance(target, int) and function_sizes.get(target, MINIMUM_FUNCTION_SIZE) < MINIMUM_FUNCTION_SIZE:
                protected_callees.add(target)
    return frozenset(protected_callees)


def _read_exception_context(
    binary: Any, unwind_section: str | None
) -> tuple[dict[int, Any] | None, str | None, frozenset[int]]:
    """Read unwind metadata and derive protected direct-call targets."""
    exception_frames, unwind_read_error = _read_exception_frames(binary, unwind_section)
    return exception_frames, unwind_read_error, _protected_callee_addresses(binary, exception_frames)


def _unwind_context_for_function(
    binary: Any,
    function: dict[str, Any],
    unwind_inputs: tuple[str | None, dict[int, Any] | None, str | None, frozenset[int]],
) -> _UnwindContext:
    """Build one function's unwind preflight context and precise blocker."""
    unwind_section, exception_frames, unwind_read_error, protected_callee_addresses = unwind_inputs
    function_address = int(function["addr"])
    unwind_frame = _unwind_frame_for_function(unwind_section, function, exception_frames, unwind_read_error)
    unwind_blocker = _unwind_contract_blocker(binary, function, unwind_frame)
    unwind_reason = (
        "function is called from an LSDA-protected call site; exception propagation crosses the VM boundary"
        if function_address in protected_callee_addresses
        else unwind_read_error
    )
    if unwind_reason is None and unwind_blocker is not None:
        unwind_reason = unwind_blocker[1]
    return _UnwindContext(
        _function_has_unproven_unwind_metadata(
            unwind_section,
            function_address,
            exception_frames,
            _function_has_native_call(binary, function),
            unwind_frame is not None and _exception_frame_for_function(function_address, exception_frames) is None,
        )
        or function_address in protected_callee_addresses
        or unwind_read_error is not None
        or unwind_blocker is not None,
        unwind_frame,
        unwind_reason,
        unwind_blocker[0] if unwind_blocker is not None else None,
    )


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


def _canonicalize_language_unwind_functions(
    functions: list[dict[str, Any]], exception_frames: dict[int, Any] | None
) -> list[dict[str, Any]]:
    """Collapse analyzer chunks inside one language-level unwind frame."""
    if not exception_frames:
        return functions
    canonicalized: list[dict[str, Any]] = []
    seen_addresses: set[int] = set()
    for function in functions:
        address = function.get("addr")
        frame = _exception_frame_for_function(address, exception_frames) if isinstance(address, int) else None
        frame_start = getattr(frame, "function_start", None)
        frame_end = getattr(frame, "function_end", None)
        normalized_function = function
        if (
            _has_language_unwind_contract(frame)
            and isinstance(frame_start, int)
            and isinstance(frame_end, int)
            and frame_end > frame_start
        ):
            normalized_function = {
                **function,
                "addr": frame_start,
                "minaddr": frame_start,
                "maxaddr": frame_end,
                "size": frame_end - frame_start,
            }
        canonical_address = normalized_function.get("addr")
        if isinstance(canonical_address, int) and canonical_address in seen_addresses:
            continue
        if isinstance(canonical_address, int):
            seen_addresses.add(canonical_address)
        canonicalized.append(normalized_function)
    return canonicalized


def _ordinary_unwind_frame_for_function(
    unwind_section: str | None,
    function: dict[str, Any],
    exception_frames: dict[int, Any] | None,
) -> ExceptionFrame | None:
    """Build an ordinary ELF frame when valid metadata has no mapped FDE."""
    if unwind_section != ".eh_frame" or exception_frames is None:
        return None
    address = function.get("addr")
    size = function.get("size")
    if not isinstance(address, int) or not isinstance(size, int) or size <= 0:
        return None
    if _exception_frame_for_function(address, exception_frames) is not None:
        return None
    return ExceptionFrame(function_start=address, function_end=address + size)


def _unwind_frame_for_function(
    unwind_section: str | None,
    function: dict[str, Any],
    exception_frames: dict[int, Any] | None,
    unwind_read_error: str | None,
) -> Any | None:
    """Prefer parsed metadata and synthesize only after a clean ELF read."""
    frame = _exception_frame_for_function(int(function["addr"]), exception_frames)
    if frame is not None or unwind_read_error is not None:
        return frame
    return _ordinary_unwind_frame_for_function(unwind_section, function, exception_frames)


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


def _has_compact_ret_cleanup(binary: Any, function: dict[str, Any]) -> bool:
    """Keep a small callee when its return cleanup is part of the VM contract."""
    try:
        address = function["addr"]
        size = function["size"]
        raw_bytes = binary.read_bytes(address, size)
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        instructions = decoder.disasm(raw_bytes, address)
    except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError, capstone.CsError):
        return False
    for instruction in instructions:
        if instruction.mnemonic.lower() not in ("ret", "retn"):
            continue
        cleanup = classification._decode_ret_cleanup(f"{instruction.mnemonic} {instruction.op_str}".strip())
        if cleanup not in (None, 0):
            return True
    return False


def _compact_ret_addresses(binary: Any, functions: list[dict[str, Any]]) -> frozenset[int]:
    """Find small callee-cleanup functions without unbounded byte reads."""
    tiny_functions = [
        function
        for function in functions
        if isinstance(function.get("size"), int) and function["size"] < MINIMUM_FUNCTION_SIZE
    ]
    if len(tiny_functions) > _MAX_COMPACT_RET_SCAN:
        logger.warning(
            "Skipping compact-return probing for %d tiny functions; cap is %d",
            len(tiny_functions),
            _MAX_COMPACT_RET_SCAN,
        )
        return frozenset()
    return frozenset(
        int(function["addr"])
        for function in tiny_functions
        if isinstance(function.get("addr"), int) and _has_compact_ret_cleanup(binary, function)
    )


def _static_dataflow_is_complete(cfg: Any) -> bool:
    """Require CFG, liveness, and SSA coverage before lowering a function."""
    try:
        if not cfg.blocks:
            return False
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()
        if not analyzer.has_complete_liveness_coverage():
            return False
        ssa_blocks = analyzer.build_ssa_form()
    except (AttributeError, OSError, BrokenPipeError, RuntimeError, TypeError, ValueError) as exc:
        logger.debug("Static dataflow failed: %s", exc)
        return False
    return set(ssa_blocks) == set(cfg.blocks) and analyzer.has_complete_liveness_coverage()


def _has_materialized_instructions(binary: Any, function: dict[str, Any]) -> bool | None:
    """Return whether r2 exposed executable instructions for a candidate."""
    try:
        disassembly = binary.r2.cmdj(f"pdfj @ {function['addr']}")
    except (AttributeError, BrokenPipeError, OSError, RuntimeError, TypeError, ValueError):
        return None
    if not isinstance(disassembly, dict):
        return None
    return any(
        isinstance(instruction, dict) and instruction.get("type") not in {"nop", "invalid"}
        for instruction in disassembly.get("ops", [])
    )


def _ordered_functions(
    binary: Any,
    analysis_budget: int = MAX_FUNCTION_ANALYSIS_COUNT,
    unwind_section: str | None = None,
    entrypoint_addresses: frozenset[int] = frozenset(),
    dispatch_entrypoint_addresses: frozenset[int] = frozenset(),
) -> list[dict[str, Any]] | None:
    """Visit viable functions in stable application-first order before the budget."""

    raw_functions = list(binary.get_functions())
    raw_functions = [
        function for function in raw_functions if not _is_unreferenced_function_chunk(binary, function, raw_functions)
    ]
    application_entry_addresses = frozenset(
        int(function["addr"])
        for function in raw_functions
        if str(function.get("name", "")).strip().lower() in {"main", "_main", "sym.main"}
        and isinstance(function.get("addr"), int)
    )
    application_targets = _application_target_addresses(binary, raw_functions)
    application_candidates = _application_candidate_addresses(raw_functions, application_targets)
    raw_functions = _application_target_functions(binary, raw_functions, application_candidates)

    def function_order_key(function: dict[str, Any]) -> tuple[int, int]:
        if function.get("addr") in dispatch_entrypoint_addresses:
            address = function.get("addr")
            return (-1, int(address) if isinstance(address, int) else 0)
        if function.get("addr") in application_targets:
            address = function.get("addr")
            return (0, int(address) if isinstance(address, int) else 0)
        named_priority, address = _function_order_key(function)
        return (named_priority + 1, address)

    functions = sorted(raw_functions, key=function_order_key)
    plt_ranges = _plt_ranges(binary)

    def is_runtime_entrypoint(function: dict[str, Any]) -> bool:
        address = function.get("addr")
        return address not in dispatch_entrypoint_addresses and _is_runtime_entrypoint(
            function, unwind_section, entrypoint_addresses
        )

    non_tiny = [
        function
        for function in functions
        if not _address_in_ranges(function.get("addr"), plt_ranges)
        and not (isinstance(function.get("size"), int) and function["size"] < MINIMUM_FUNCTION_SIZE)
        and not is_runtime_entrypoint(function)
    ]
    if len(non_tiny) > analysis_budget:
        logger.warning(
            "Skipping code virtualization: non-tiny function population exceeds the VM analysis budget (%d > %d)",
            len(non_tiny),
            analysis_budget,
        )
        return None

    compact_ret_addresses = _compact_ret_addresses(binary, functions)
    viable = [
        function
        for function in functions
        if not (
            isinstance(function.get("size"), int)
            and function["size"] < MINIMUM_FUNCTION_SIZE
            and function.get("addr") not in compact_ret_addresses
            and function.get("addr") not in application_candidates
            and function.get("addr") not in dispatch_entrypoint_addresses
        )
        and not _address_in_ranges(function.get("addr"), plt_ranges)
    ]

    application_addresses = application_entry_addresses | application_candidates | dispatch_entrypoint_addresses
    if len(raw_functions) > _LARGE_APPLICATION_POPULATION and application_addresses:
        application_functions = [function for function in viable if function.get("addr") in application_addresses]
        if application_functions:
            viable = application_functions

    runtime_free = [function for function in viable if not is_runtime_entrypoint(function)]
    if runtime_free:
        viable = runtime_free
    if len(viable) <= analysis_budget:
        return viable
    candidates = [function for function in viable if not is_runtime_entrypoint(function)]
    if len(candidates) > analysis_budget:
        logger.warning(
            "Skipping code virtualization: function population exceeds the VM analysis budget (%d > %d)",
            len(candidates),
            analysis_budget,
        )
        return None
    return candidates


def apply_code_virtualization(pass_instance: Any, binary: Any) -> dict[str, Any]:
    """Apply code virtualization using the pass instance's transformation seams."""
    pass_instance._reset_random()
    target_diagnostic = _target_diagnostic(pass_instance, binary)
    if target_diagnostic is not None:
        logger.warning("Skipping code virtualization for unsupported target: %s", target_diagnostic)
        return _empty_result(target_diagnostic)
    pass_instance._ensure_analyzed(binary)
    logger.info("Applying code virtualization")

    virtualized, skipped, total_insns, total_bytecode, unsupported_total, partial_total = (0, 0, 0, 0, 0, 0)
    unsupported: list[dict[str, Any]] = []
    partial: list[dict[str, Any]] = []
    covered_ranges: list[tuple[int, int]] = []
    executable_ranges = _executable_ranges(binary)
    unwind_section = _unwind_metadata_name(binary)
    exception_frames, unwind_read_error, protected_callee_addresses = _read_exception_context(binary, unwind_section)
    ordered_functions = _ordered_functions(
        binary,
        pass_instance.max_function_analysis_count,
        unwind_section,
        _entrypoint_addresses(binary) | _runtime_initialization_addresses(binary),
        _dispatch_entrypoint_addresses(pass_instance, binary) | protected_callee_addresses,
    )
    if ordered_functions is None:
        return _analysis_budget_result(pass_instance.max_function_analysis_count)
    ordered_functions = _canonicalize_language_unwind_functions(ordered_functions, exception_frames)

    for func in ordered_functions:
        if virtualized >= pass_instance.max_functions:
            break
        function_address = func.get("addr")
        if executable_ranges and not _address_in_ranges(function_address, executable_ranges):
            continue
        if _address_in_ranges(function_address, covered_ranges):
            continue
        if (
            func.get("size", 0) < MINIMUM_FUNCTION_SIZE
            and func.get("addr") not in protected_callee_addresses
            and not _has_compact_ret_cleanup(binary, func)
        ):
            continue
        if _exceeds_function_size_budget(func, pass_instance.max_function_size):
            skipped, unsupported_total = _skip_oversized_function(
                pass_instance, func, unsupported, skipped, unsupported_total
            )
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
        if (
            not pass_instance.virtualize_dispatch
            and (computed_jump := pass_instance._find_computed_jump(binary, func)) is not None
        ):
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
            unwind=_unwind_context_for_function(
                binary,
                func,
                (unwind_section, exception_frames, unwind_read_error, protected_callee_addresses),
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
