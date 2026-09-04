#!/usr/bin/env python3
"""Run a bounded, evidence-preserving analysis benchmark on a binary pair."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections.abc import Callable
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r2morph.adapters.process import ProcessTimeoutError, run_process
from r2morph.core.binary import Binary
from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.elf_structs import PT_LOAD
from scripts.protection_maturity_baseline import (
    DEFAULT_MUTATION_NAME,
    _build_mutation_pass,
    _parse_pass_names,
    discover_executables,
)
from tests.integration.elf_emulator import emulate_exit_code

_COMMANDS = {"radare2": "r2", "objdump": "objdump", "ida-pro": "ida64", "ghidra": "ghidra"}
_COMMAND_ENVIRONMENT = {"ghidra": "GHIDRA_HEADLESS"}
_PYTHON_MODULES = {"angr": "angr", "triton": "triton", "unicorn": "unicorn"}
_EXPECTED_TOOLS = ("radare2", "objdump", "angr", "unicorn", "triton", "ida-pro", "ghidra")
_DISASSEMBLY_LINE = re.compile(r"^\s*[0-9a-f]+:\s", re.IGNORECASE)
_COMMAND_TIMEOUT_SECONDS = 30
_GHIDRA_ANALYSIS_TIMEOUT_SECONDS = 60
_PASS_STATUS_FIELDS = {"applied": "applied", "omitted": "omitted", "no-op": "no_op", "error": "errors"}
_GHIDRA_SCRIPT = Path(__file__).with_name("ghidra")
_GHIDRA_COUNT_PATTERN = re.compile(r"R2MORPH_FUNCTION_COUNT=(?:(?P<program>[^=\r\n]+)=)?(?P<count>\d+)")
_PF_EXECUTE = 1
_MAX_X86_INSTRUCTION_BYTES = 15
_TRITON_INSTRUCTION_BUDGET = 50_000


def _configured_executable(tool: str) -> str | None:
    environment_name = _COMMAND_ENVIRONMENT.get(tool)
    if environment_name:
        configured = os.environ.get(environment_name)
        if configured:
            return configured if Path(configured).is_file() else None
    return shutil.which(_COMMANDS[tool])


def _availability(tool: str) -> tuple[bool, str]:
    if tool in _COMMANDS:
        command = _configured_executable(tool)
        return (True, command) if command else (False, f"executable {_COMMANDS[tool]!r} is unavailable")
    module = _PYTHON_MODULES[tool]
    return (True, module) if importlib.util.find_spec(module) else (False, f"module {module!r} is unavailable")


def _radare2_metric(path: Path) -> dict[str, object]:
    executable = shutil.which("r2")
    if executable is None:
        return {"status": "unavailable", "detail": "executable r2 is unavailable"}
    try:
        result = run_process([executable, "-q0", "-c", "aa;aflj", str(path)], timeout=_COMMAND_TIMEOUT_SECONDS)
        functions = json.loads(result.stdout_text)
    except (OSError, ProcessTimeoutError, json.JSONDecodeError) as error:
        return {"status": "error", "detail": type(error).__name__}
    return {
        "status": "completed",
        "return_code": result.returncode,
        "functions": len(functions) if isinstance(functions, list) else 0,
    }


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


def _angr_metric(path: Path) -> dict[str, object]:
    angr = import_module("angr")
    started = time.perf_counter()
    project = angr.Project(str(path), auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    return {
        "status": "completed",
        "functions": len(cfg.kb.functions),
        "duration_seconds": time.perf_counter() - started,
    }


def _unicorn_metric(path: Path) -> dict[str, object]:
    started = time.perf_counter()
    exit_code = emulate_exit_code(path)
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


def _parse_ghidra_function_counts(output: str) -> dict[str, int]:
    counts = {
        match.group("program"): int(match.group("count"))
        for match in _GHIDRA_COUNT_PATTERN.finditer(output)
        if match.group("program") is not None
    }
    if not counts:
        raise ValueError("Ghidra function count markers are missing")
    return counts


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
            timeout=_COMMAND_TIMEOUT_SECONDS,
        )
    if result.returncode != 0:
        raise RuntimeError(f"Ghidra headless exited with status {result.returncode}")
    count = _parse_ghidra_function_count(result.stdout_text + result.stderr_text)
    return {"status": "completed", "functions": count, "duration_seconds": time.perf_counter() - started}


def _binary_metric(path: Path) -> dict[str, object]:
    with Binary(path) as binary:
        binary.analyze("aa")
        return {"status": "completed", "functions": len(binary.get_functions())}


_METRICS: dict[str, Callable[[Path], dict[str, object]]] = {
    "radare2": _radare2_metric,
    "objdump": _objdump_metric,
    "angr": _angr_metric,
    "unicorn": _unicorn_metric,
    "triton": _triton_metric,
    "ghidra": _ghidra_metric,
    "custom": _binary_metric,
}


def _measure_tool(tool: str, original: Path, protected: Path) -> dict[str, object]:
    available, reason = _availability(tool)
    if not available:
        return {"tool": tool, "status": "unavailable", "reason": reason}
    measure = _METRICS.get(tool)
    if measure is None:
        return {"tool": tool, "status": "unavailable", "reason": "no local adapter configured"}
    try:
        before = measure(original)
        after = measure(protected)
    except Exception as error:  # Tool boundary records failures without hiding the campaign result.
        return {"tool": tool, "status": "error", "error_type": type(error).__name__}
    return {"tool": tool, "status": "completed", "original": before, "protected": after, "changed": before != after}


def _protected_copy(original: Path, directory: Path, pass_name: str) -> tuple[Path, dict[str, object]]:
    protected = directory / "protected"
    shutil.copyfile(original, protected)
    binary = Binary(protected, writable=True)
    binary.open()
    try:
        stats = _build_mutation_pass(pass_name, 20260827).apply(binary)
        binary.save()
    finally:
        binary.close()
    return protected, _pass_result(stats, pass_name)


def _pass_result(stats: dict[str, object], pass_name: str = DEFAULT_MUTATION_NAME) -> dict[str, object]:
    virtualized = stats.get("functions_virtualized", 0)
    unsupported = stats.get("unsupported_functions_total", 0)
    applied = virtualized
    if not isinstance(applied, int) or applied == 0:
        applied = stats.get("mutations_applied", 0)
    if isinstance(applied, int) and applied > 0:
        status = "applied"
    elif isinstance(unsupported, int) and unsupported > 0:
        status = "omitted"
    else:
        status = "no-op"
    result: dict[str, object] = {
        "pass_name": pass_name,
        "status": status,
    }
    if pass_name == DEFAULT_MUTATION_NAME:
        result["functions_virtualized"] = virtualized
        result["unsupported_functions"] = unsupported
    else:
        result["mutations_applied"] = applied
    return result


def _pass_summary(samples: list[dict[str, object]]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for sample in samples:
        rows = sample.get("passes", [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            pass_name = row.get("pass_name")
            status = row.get("status")
            if not isinstance(pass_name, str) or not isinstance(status, str):
                continue
            counters = summary.setdefault(
                pass_name,
                {
                    "samples": 0,
                    "applied": 0,
                    "omitted": 0,
                    "no_op": 0,
                    "errors": 0,
                    "functions_virtualized": 0,
                    "unsupported_functions": 0,
                },
            )
            counters["samples"] += 1
            status_field = _PASS_STATUS_FIELDS.get(status)
            if status_field is not None:
                counters[status_field] += 1
            for field in ("functions_virtualized", "unsupported_functions"):
                value = row.get(field)
                if isinstance(value, int):
                    counters[field] += value
            if "mutations_applied" in row:
                counters.setdefault("mutations_applied", 0)
                value = row["mutations_applied"]
                if isinstance(value, int):
                    counters["mutations_applied"] += value
    return dict(sorted(summary.items()))


def _measure_pair_tools(original: Path, protected: Path) -> list[dict[str, object]]:
    tools = [_measure_tool(tool, original, protected) for tool in _EXPECTED_TOOLS]
    tools.append(
        {
            "tool": "custom",
            "status": "completed",
            "original": _binary_metric(original),
            "protected": _binary_metric(protected),
        }
    )
    return tools


def benchmark_pair(
    original: Path,
    protected: Path | None = None,
    pass_names: tuple[str, ...] = (DEFAULT_MUTATION_NAME,),
) -> dict[str, object]:
    """Benchmark every configured analyzer and preserve unavailable evidence."""
    if not original.is_file():
        raise ValueError(f"original binary does not exist: {original}")
    with tempfile.TemporaryDirectory(prefix="r2morph-adversarial-") as directory:
        pass_rows: list[dict[str, object]] = []
        tools: list[dict[str, object]] = []
        if protected is None:
            protected_path = Path(directory) / "protected"
            for pass_name in pass_names:
                try:
                    protected_path, pass_row = _protected_copy(original, Path(directory), pass_name)
                except Exception as error:  # Transformation boundary records per-pass failures.
                    pass_rows.append(
                        {
                            "pass_name": pass_name,
                            "status": "error",
                            "error_type": type(error).__name__,
                        }
                    )
                    continue
                pass_rows.append(pass_row)
                tools.extend({**tool, "pass_name": pass_name} for tool in _measure_pair_tools(original, protected_path))
        else:
            protected_path = protected
            tools = _measure_pair_tools(original, protected_path)
    report: dict[str, object] = {
        "schema_version": 3,
        "original": original.name,
        "protected": protected_path.name,
        "tools": tools,
    }
    if protected is None:
        report["passes"] = pass_rows
        report["pass_names"] = list(pass_names)
    return report


def benchmark_corpus(
    dataset: Path,
    pass_names: tuple[str, ...] = (DEFAULT_MUTATION_NAME,),
) -> dict[str, object]:
    """Run the pair benchmark for every supported executable in the corpus."""
    fixtures = discover_executables(dataset)
    if not fixtures:
        raise ValueError(f"no supported executable fixtures found in {dataset}")
    if not pass_names:
        raise ValueError("at least one corpus pass is required")
    samples = [benchmark_pair(fixture, pass_names=pass_names) for fixture in fixtures]
    completed_tools = sum(
        1
        for sample in samples
        for tool in sample["tools"]
        if isinstance(tool, dict) and tool.get("status") == "completed"
    )
    unavailable_tools = sum(
        1
        for sample in samples
        for tool in sample["tools"]
        if isinstance(tool, dict) and tool.get("status") == "unavailable"
    )
    return {
        "schema_version": 3,
        "measurement": "protection-adversarial-corpus",
        "corpus": dataset.name,
        "sample_count": len(samples),
        "samples": samples,
        "pass_summary": _pass_summary(samples),
        "summary": {
            "completed_tool_runs": completed_tools,
            "unavailable_tool_runs": unavailable_tools,
            "error_tool_runs": len(fixtures) * len(pass_names) * (len(_EXPECTED_TOOLS) + 1)
            - completed_tools
            - unavailable_tools,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("original", type=Path, nargs="?")
    selection.add_argument("--all", action="store_true", dest="all_fixtures")
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--protected", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--passes",
        default=DEFAULT_MUTATION_NAME,
        help="comma-separated pass names or 'all' (default: CodeVirtualization)",
    )
    args = parser.parse_args()
    if args.all_fixtures and args.protected:
        parser.error("--protected is valid only with one original binary")
    try:
        pass_names = _parse_pass_names(args.passes)
    except ValueError as error:
        parser.error(str(error))
    report = (
        benchmark_corpus(args.dataset, pass_names)
        if args.all_fixtures
        else benchmark_pair(args.original, args.protected)
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
