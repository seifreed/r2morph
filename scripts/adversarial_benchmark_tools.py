"""Analyzer adapters and bounded tool execution for adversarial campaigns."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from importlib import import_module
from pathlib import Path
from queue import Empty
from typing import Any

from r2morph.adapters.angr_import import import_angr_modules
from r2morph.adapters.process import ProcessTimeoutError, run_process
from r2morph.core.binary import Binary
from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.elf_structs import PT_LOAD
from scripts.adversarial_benchmark_constants import (
    _ADVERSARIAL_ALL_PASS_NAMES,
    _ANGR_DECOMPILER_FUNCTION_LIMIT,
    _ANSI_ESCAPE,
    _BINARY_NINJA_PYTHON_PATH_ENV,
    _BINARY_NINJA_PYTHON_PATHS,
    _COMMAND_ENVIRONMENT,
    _COMMAND_TIMEOUT_SECONDS,
    _COMMANDS,
    _DISASSEMBLY_LINE,
    _GHIDRA_ANALYSIS_TIMEOUT_SECONDS,
    _GHIDRA_COUNT_PATTERN,
    _GHIDRA_DECOMPILER_PATTERN,
    _GHIDRA_PROCESS_TIMEOUT_SECONDS,
    _GHIDRA_SCRIPT,
    _IDA_RESULT_SUFFIX,
    _IDA_SCRIPT,
    _IN_PROCESS_TOOL_TIMEOUT_SECONDS,
    _IN_PROCESS_TOOLS,
    _MAX_X86_INSTRUCTION_BYTES,
    _PF_EXECUTE,
    _PYTHON_MODULES,
    _TRITON_INSTRUCTION_BUDGET,
)
from scripts.adversarial_benchmark_passes import _pass_result
from scripts.protection_maturity_baseline import _build_mutation_pass, _parse_pass_names
from tests.integration.elf_emulator import emulate_exit_code


class _ToolCapabilityUnavailableError(RuntimeError):
    """The analyzer is present but cannot execute this input's ISA."""


def _tool_failure_result(tool: str, error: Exception) -> dict[str, object]:
    if isinstance(error, _ToolCapabilityUnavailableError):
        return {"tool": tool, "status": "unavailable", "reason": str(error)}
    result: dict[str, object] = {"tool": tool, "status": "error", "error_type": type(error).__name__}
    if str(error):
        result["detail"] = str(error)
    return result


def _parse_adversarial_pass_names(value: str) -> tuple[str, ...]:
    if value.strip().lower() == "all":
        return _ADVERSARIAL_ALL_PASS_NAMES
    return _parse_pass_names(value)


def _configured_executable(tool: str) -> str | None:
    environment_name = _COMMAND_ENVIRONMENT.get(tool)
    if environment_name:
        configured = os.environ.get(environment_name)
        if configured:
            return configured if Path(configured).is_file() else None
    return shutil.which(_COMMANDS[tool])


def _prepare_optional_module_path(tool: str) -> None:
    """Expose an installed analyzer bundle before probing its Python module."""
    if tool != "binary-ninja":
        return
    candidates = []
    configured = os.environ.get(_BINARY_NINJA_PYTHON_PATH_ENV)
    if configured:
        candidates.append(Path(configured))
    candidates.extend(_BINARY_NINJA_PYTHON_PATHS)
    for candidate in candidates:
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))


def _availability(tool: str) -> tuple[bool, str]:
    if tool == "angr":
        imported = import_angr_modules()
        if imported.available:
            return True, "angr"
        return False, "module 'angr' cannot be imported through the compatibility adapter"
    if tool in _COMMANDS:
        command = _configured_executable(tool)
        return (True, command) if command else (False, f"executable {_COMMANDS[tool]!r} is unavailable")
    _prepare_optional_module_path(tool)
    module = _PYTHON_MODULES[tool]
    if importlib.util.find_spec(module) is None:
        return False, f"module {module!r} is unavailable"
    try:
        import_module(module)
    # Optional analyzer imports can fail for ABI, license, or dependency reasons.
    except Exception as error:
        return False, f"module {module!r} cannot be imported: {type(error).__name__}: {error}"
    return True, module


def _radare2_metric(path: Path) -> dict[str, object]:
    executable = shutil.which("r2")
    if executable is None:
        return {"status": "unavailable", "detail": "executable r2 is unavailable"}
    try:
        result = run_process([executable, "-q0", "-c", "aa;aflj", str(path)], timeout=_COMMAND_TIMEOUT_SECONDS)
        functions = json.loads(result.stdout_text)
    except (OSError, ProcessTimeoutError, json.JSONDecodeError) as error:
        return {"status": "error", "detail": type(error).__name__}
    metric: dict[str, object] = {
        "status": "completed",
        "return_code": result.returncode,
        "functions": len(functions) if isinstance(functions, list) else 0,
    }
    function_address = next(
        (
            function.get("offset", function.get("addr"))
            for function in functions
            if isinstance(function, dict) and isinstance(function.get("offset", function.get("addr")), int)
        ),
        None,
    )
    if function_address is None:
        metric.update(
            {
                "decompiler_status": "unavailable",
                "decompiler_reason": "no recovered function entrypoint",
                "decompiler_entrypoints": 0,
                "decompiler_lines": 0,
                "decompiler_bytes": 0,
            }
        )
        return metric
    try:
        decompiler_result = run_process(
            [
                executable,
                "-q0",
                "-e",
                "scr.color=false",
                "-c",
                f"aa;pdc @ {function_address};q",
                str(path),
            ],
            timeout=_COMMAND_TIMEOUT_SECONDS,
        )
        decompiler_text = _ANSI_ESCAPE.sub("", decompiler_result.stdout_text)
        decompiler_lines = [line for line in decompiler_text.splitlines() if line.strip()]
        metric.update(
            {
                "decompiler_status": "completed" if decompiler_lines else "unavailable",
                "decompiler_entrypoints": int(bool(decompiler_lines)),
                "decompiler_lines": len(decompiler_lines),
                "decompiler_bytes": len(decompiler_text.encode("utf-8")),
            }
        )
        if not decompiler_lines:
            metric["decompiler_reason"] = "decompiler returned no pseudocode"
    except (OSError, ProcessTimeoutError) as error:
        metric.update(
            {
                "decompiler_status": "error",
                "decompiler_reason": type(error).__name__,
                "decompiler_entrypoints": 0,
                "decompiler_lines": 0,
                "decompiler_bytes": 0,
            }
        )
    return metric


def _objdump_metric(path: Path) -> dict[str, object]:
    executable = shutil.which("objdump")
    if executable is None:
        return {"status": "unavailable", "detail": "executable objdump is unavailable"}
    try:
        completed = run_process([executable, "-d", "--no-show-raw-insn", str(path)], timeout=_COMMAND_TIMEOUT_SECONDS)
    except (OSError, ProcessTimeoutError) as error:
        return {"status": "error", "detail": type(error).__name__}
    count = sum(bool(_DISASSEMBLY_LINE.match(line)) for line in completed.stdout_text.splitlines())
    return {"status": "completed", "return_code": completed.returncode, "instruction_lines": count}


def _is_binary_ninja_license_error(error: RuntimeError) -> bool:
    return "license" in str(error).lower()


def _angr_metric(path: Path) -> dict[str, object]:
    imported = import_angr_modules(project=True)
    if not imported.available or imported.project is None:
        raise _ToolCapabilityUnavailableError("module 'angr' cannot be imported through the compatibility adapter")
    project_class = imported.project
    started = time.perf_counter()
    project = project_class(str(path), auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    functions = sorted(
        (
            function
            for function in cfg.kb.functions.values()
            if isinstance(getattr(function, "addr", None), int)
            and not bool(getattr(function, "is_simprocedure", False))
            and not bool(getattr(function, "is_plt", False))
        ),
        key=lambda function: function.addr,
    )[:_ANGR_DECOMPILER_FUNCTION_LIMIT]
    decompiler_entrypoints = 0
    decompiler_lines = 0
    decompiler_bytes = 0
    decompiler_failures = 0
    for function in functions:
        try:
            result = project.analyses.Decompiler(function, cfg=cfg)
            text = getattr(getattr(result, "codegen", None), "text", "")
        except (AttributeError, RuntimeError, TypeError, ValueError):
            decompiler_failures += 1
            continue
        if not isinstance(text, str) or not text.strip():
            continue
        decompiler_entrypoints += 1
        decompiler_lines += sum(bool(line.strip()) for line in text.splitlines())
        decompiler_bytes += len(text.encode("utf-8"))
    metric: dict[str, object] = {
        "status": "completed",
        "functions": len(cfg.kb.functions),
        "duration_seconds": time.perf_counter() - started,
        "decompiler_status": "completed" if decompiler_entrypoints else "unavailable",
        "decompiler_entrypoints": decompiler_entrypoints,
        "decompiler_lines": decompiler_lines,
        "decompiler_bytes": decompiler_bytes,
        "decompiler_function_limit": _ANGR_DECOMPILER_FUNCTION_LIMIT,
        "decompiler_failures": decompiler_failures,
    }
    if not decompiler_entrypoints:
        metric["decompiler_reason"] = "angr produced no decompiler output"
    return {
        **metric,
    }


def _binary_ninja_metric(path: Path) -> dict[str, object]:
    binaryninja = import_module("binaryninja")
    started = time.perf_counter()
    try:
        with binaryninja.load(str(path), update_analysis=False) as view:
            view.update_analysis_and_wait()
            functions = tuple(view.functions)
            decompiler = _binary_ninja_decompiler_metrics(functions)
    except RuntimeError as error:
        if _is_binary_ninja_license_error(error):
            raise _ToolCapabilityUnavailableError("analyzer license is unavailable") from error
        raise
    return {
        "status": "completed",
        "functions": len(functions),
        **decompiler,
        "duration_seconds": time.perf_counter() - started,
    }


def _binary_ninja_decompiler_metrics(functions: Sequence[Any]) -> dict[str, object]:
    """Collect bounded HLIL output so Binary Ninja is comparable to other analyzers."""
    entrypoints = 0
    lines = 0
    byte_count = 0
    failures = 0
    ordered_functions = sorted(functions, key=lambda function: getattr(function, "start", 0))
    for function in ordered_functions[:_ANGR_DECOMPILER_FUNCTION_LIMIT]:
        try:
            high_level_il = function.hlil
            text = str(high_level_il)
        except (AttributeError, RuntimeError, TypeError, ValueError):
            failures += 1
            continue
        if not text.strip():
            continue
        entrypoints += 1
        lines += sum(bool(line.strip()) for line in text.splitlines())
        byte_count += len(text.encode("utf-8"))
    metric: dict[str, object] = {
        "decompiler_status": "completed" if entrypoints else "unavailable",
        "decompiler_entrypoints": entrypoints,
        "decompiler_lines": lines,
        "decompiler_bytes": byte_count,
        "decompiler_function_limit": _ANGR_DECOMPILER_FUNCTION_LIMIT,
        "decompiler_failures": failures,
    }
    if not entrypoints:
        metric["decompiler_reason"] = "Binary Ninja produced no HLIL output"
    return metric


def _unicorn_metric(path: Path) -> dict[str, object]:
    started = time.perf_counter()
    try:
        exit_code = emulate_exit_code(path)
    except Exception as error:
        if type(error).__name__ == "UcError":
            raise _ToolCapabilityUnavailableError(
                "the installed x86 emulator does not support an instruction in this fixture"
            ) from error
        raise
    return {"status": "completed", "exit_code": exit_code, "duration_seconds": time.perf_counter() - started}


def _executable_segment_bytes(path: Path) -> tuple[tuple[int, bytes], ...]:
    raw = path.read_bytes()
    segments: list[tuple[int, bytes]] = []
    for segment in ELFHandler(path).get_segments():
        if segment["type"] != PT_LOAD or not int(segment["flags"]) & _PF_EXECUTE:
            continue
        offset = int(segment["offset"])
        size = int(segment["filesz"])
        end = offset + size
        if offset < 0 or size < 0 or end > len(raw):
            raise ValueError("executable ELF segment exceeds file bounds")
        segments.append((int(segment["vaddr"]), raw[offset:end]))
    if not segments:
        raise ValueError("ELF contains no executable load segment")
    return tuple(segments)


def _triton_metric(path: Path) -> dict[str, object]:
    triton = import_module("triton")
    context = triton.TritonContext(triton.ARCH.X86_64)
    started = time.perf_counter()
    decoded = 0
    supported = 0
    symbolic_expressions = 0
    invalid_bytes = 0
    budget_exhausted = False
    for address, code in _executable_segment_bytes(path):
        offset = 0
        while offset < len(code):
            if decoded + invalid_bytes >= _TRITON_INSTRUCTION_BUDGET:
                budget_exhausted = True
                break
            instruction = triton.Instruction(address + offset, code[offset : offset + _MAX_X86_INSTRUCTION_BYTES])
            try:
                result = context.processing(instruction)
            except (RuntimeError, TypeError, ValueError):
                invalid_bytes += 1
                offset += 1
                continue
            size = instruction.getSize()
            if size < 1:
                invalid_bytes += 1
                offset += 1
                continue
            decoded += 1
            supported += result == triton.EXCEPTION.NO_FAULT
            symbolic_expressions += len(instruction.getSymbolicExpressions())
            offset += size
        if budget_exhausted:
            break
    return {
        "status": "completed",
        "decoded_instructions": decoded,
        "semantically_supported_instructions": supported,
        "symbolic_expressions": symbolic_expressions,
        "invalid_bytes": invalid_bytes,
        "instruction_budget_exhausted": budget_exhausted,
        "duration_seconds": time.perf_counter() - started,
    }


def _parse_ghidra_function_count(output: str) -> int:
    match = _GHIDRA_COUNT_PATTERN.search(output)
    if match is None:
        raise ValueError("Ghidra function count marker is missing")
    return int(match.group("count"))


def _ida_metric(path: Path) -> dict[str, object]:
    executable = _configured_executable("ida-pro")
    if executable is None:
        raise FileNotFoundError("IDA headless executable is unavailable")
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r2morph-ida-") as directory:
        analysis_path = Path(directory) / path.name
        result_path = Path(f"{analysis_path}{_IDA_RESULT_SUFFIX}")
        shutil.copyfile(path, analysis_path)
        result = run_process(
            [executable, "-A", f"-S{_IDA_SCRIPT}", str(analysis_path)],
            timeout=_GHIDRA_ANALYSIS_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            raise RuntimeError(f"IDA headless exited with status {result.returncode}")
        if not result_path.is_file():
            raise RuntimeError("IDA function count result is missing")
        count = int(result_path.read_text(encoding="ascii"))
        decompiler_path = Path(f"{analysis_path}.decompiler")
        decompiler = {"entrypoints": 0, "lines": 0, "bytes": 0}
        if decompiler_path.is_file():
            values = json.loads(decompiler_path.read_text(encoding="utf-8"))
            if isinstance(values, dict):
                decompiler = {field: int(values.get(field, 0)) for field in ("entrypoints", "lines", "bytes")}
    metric: dict[str, object] = {
        "status": "completed",
        "functions": count,
        "duration_seconds": time.perf_counter() - started,
        "decompiler_status": "completed" if decompiler["entrypoints"] else "unavailable",
        "decompiler_entrypoints": decompiler["entrypoints"],
        "decompiler_lines": decompiler["lines"],
        "decompiler_bytes": decompiler["bytes"],
    }
    if not decompiler["entrypoints"]:
        metric["decompiler_reason"] = "no decompiler output was produced"
    return metric


def _parse_ghidra_function_counts(output: str) -> dict[str, int]:
    counts = {
        match.group("program"): int(match.group("count"))
        for match in _GHIDRA_COUNT_PATTERN.finditer(output)
        if match.group("program") is not None
    }
    if not counts:
        raise ValueError("Ghidra function count markers are missing")
    return counts


def _parse_ghidra_decompiler_metrics(output: str) -> dict[str, dict[str, int]]:
    return {
        match.group("program"): {
            "decompiler_entrypoints": int(match.group("entrypoints")),
            "decompiler_lines": int(match.group("lines")),
            "decompiler_bytes": int(match.group("bytes")),
        }
        for match in _GHIDRA_DECOMPILER_PATTERN.finditer(output)
    }


def _ghidra_metric(path: Path) -> dict[str, object]:
    executable = _configured_executable("ghidra")
    if executable is None:
        raise FileNotFoundError("Ghidra headless executable is unavailable")
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r2morph-ghidra-") as project_dir:
        result = run_process(
            [
                executable,
                project_dir,
                "analysis",
                "-import",
                path,
                "-scriptPath",
                _GHIDRA_SCRIPT,
                "-postscript",
                "CountFunctions.java",
                "-analysisTimeoutPerFile",
                str(_GHIDRA_ANALYSIS_TIMEOUT_SECONDS),
                "-deleteProject",
                "-okToDelete",
            ],
            timeout=_GHIDRA_PROCESS_TIMEOUT_SECONDS,
        )
    if result.returncode != 0:
        raise RuntimeError(f"Ghidra headless exited with status {result.returncode}")
    output = result.stdout_text + result.stderr_text
    count = _parse_ghidra_function_count(output)
    decompiler = _parse_ghidra_decompiler_metrics(output)
    values = next(
        iter(decompiler.values()), {"decompiler_entrypoints": 0, "decompiler_lines": 0, "decompiler_bytes": 0}
    )
    metric: dict[str, object] = {
        "status": "completed",
        "functions": count,
        "duration_seconds": time.perf_counter() - started,
        **values,
        "decompiler_status": "completed" if values["decompiler_entrypoints"] else "unavailable",
    }
    if not values["decompiler_entrypoints"]:
        metric["decompiler_reason"] = "no decompiler output was produced"
    return metric


def _binary_metric(path: Path) -> dict[str, object]:
    with Binary(path) as binary:
        binary.analyze("aa")
        return {"status": "completed", "functions": len(binary.get_functions())}


def _measure_tool_unbounded(
    tool: str,
    original: Path,
    protected: Path,
    original_metric: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if tool == "custom":
        before = dict(original_metric) if original_metric is not None else _binary_metric(original)
        after = _binary_metric(protected)
        return {"tool": tool, "status": "completed", "original": before, "protected": after, "changed": before != after}
    available, reason = _availability(tool)
    if not available:
        return {"tool": tool, "status": "unavailable", "reason": reason}
    measure = _METRICS.get(tool)
    if measure is None:
        return {"tool": tool, "status": "unavailable", "reason": "no local adapter configured"}
    try:
        before = dict(original_metric) if original_metric is not None else measure(original)
        after = measure(protected)
    except Exception as error:  # Tool boundary records failures without hiding the campaign result.
        return _tool_failure_result(tool, error)
    return {"tool": tool, "status": "completed", "original": before, "protected": after, "changed": before != after}


def _measure_tool_worker(
    tool: str,
    original: str,
    protected: str,
    result_queue: Any,
    original_metric: dict[str, object] | None,
) -> None:
    """Run an in-process analyzer in a killable child process."""
    try:
        result_queue.put(_measure_tool_unbounded(tool, Path(original), Path(protected), original_metric))
    except Exception as error:
        result_queue.put(_tool_failure_result(tool, error))


def _measure_tool_bounded(
    tool: str,
    original: Path,
    protected: Path,
    timeout: float = _IN_PROCESS_TOOL_TIMEOUT_SECONDS,
    original_metric: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Preserve a tool row even when an in-process analyzer hangs."""
    if tool not in _IN_PROCESS_TOOLS:
        return _measure_tool_unbounded(tool, original, protected, original_metric)
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_measure_tool_worker,
        args=(
            tool,
            str(original),
            str(protected),
            result_queue,
            dict(original_metric) if original_metric is not None else None,
        ),
    )
    process.start()
    process.join(timeout)
    if process.is_alive():
        process.terminate()
        process.join(5.0)
        if process.is_alive():
            process.kill()
            process.join()
        result_queue.close()
        result_queue.join_thread()
        return {
            "tool": tool,
            "status": "error",
            "error_type": "ProcessTimeoutError",
            "detail": f"analyzer exceeded {timeout} seconds",
        }
    try:
        result = result_queue.get(timeout=1.0)
    except Empty:
        result = {
            "tool": tool,
            "status": "error",
            "error_type": "ProcessExitWithoutResult",
            "detail": f"analyzer worker exited with status {process.exitcode}",
        }
    finally:
        result_queue.close()
        result_queue.join_thread()
    if not isinstance(result, dict) or result.get("tool") != tool:
        return {
            "tool": tool,
            "status": "error",
            "error_type": "InvalidWorkerResult",
            "detail": "analyzer worker returned an invalid result",
        }
    return result


def _measure_tool(
    tool: str,
    original: Path,
    protected: Path,
    original_metric: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return _measure_tool_bounded(tool, original, protected, original_metric=original_metric)


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _protected_copy_worker(
    original: Path,
    directory: Path,
    pass_name: str,
    progress_path: Path,
) -> tuple[Path, dict[str, object]]:
    protected = directory / "protected"
    shutil.copyfile(original, protected)
    binary = Binary(protected, writable=True)
    progress_path.write_text("binary_analysis\n", encoding="utf-8")
    binary.open()
    try:
        # Several passes consume function, block, import, and code-cave
        # metadata. The benchmark must exercise the same analyzed input path
        # as the production pipeline before classifying a pass as no-op.
        binary.analyze("aa")
        progress_path.write_text("mutation\n", encoding="utf-8")
        stats = _build_mutation_pass(pass_name, 20260827).apply(binary)
        binary.save()
    finally:
        binary.close()
    return protected, _pass_result(stats, pass_name)


_METRICS: dict[str, Callable[[Path], dict[str, object]]] = {
    "radare2": _radare2_metric,
    "objdump": _objdump_metric,
    "angr": _angr_metric,
    "binary-ninja": _binary_ninja_metric,
    "unicorn": _unicorn_metric,
    "triton": _triton_metric,
    "ida-pro": _ida_metric,
    "ghidra": _ghidra_metric,
    "custom": _binary_metric,
}
