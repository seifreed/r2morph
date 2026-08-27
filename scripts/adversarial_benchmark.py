#!/usr/bin/env python3
"""Run a bounded, evidence-preserving analysis benchmark on a binary pair."""

from __future__ import annotations

import argparse
import importlib.util
import json
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
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code

_COMMANDS = {"radare2": "r2", "objdump": "objdump", "ida-pro": "ida64", "ghidra": "ghidra", "binary-ninja": "bndb"}
_PYTHON_MODULES = {"angr": "angr", "triton": "triton", "unicorn": "unicorn"}
_EXPECTED_TOOLS = ("radare2", "objdump", "angr", "unicorn", "triton", "ida-pro", "ghidra", "binary-ninja")
_DISASSEMBLY_LINE = re.compile(r"^\s*[0-9a-f]+:\s", re.IGNORECASE)
_COMMAND_TIMEOUT_SECONDS = 30


def _availability(tool: str) -> tuple[bool, str]:
    if tool in _COMMANDS:
        command = shutil.which(_COMMANDS[tool])
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


def _binary_metric(path: Path) -> dict[str, object]:
    with Binary(path) as binary:
        binary.analyze("aa")
        return {"status": "completed", "functions": len(binary.get_functions())}


_METRICS: dict[str, Callable[[Path], dict[str, object]]] = {
    "radare2": _radare2_metric,
    "objdump": _objdump_metric,
    "angr": _angr_metric,
    "unicorn": _unicorn_metric,
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


def _protected_copy(original: Path, directory: Path) -> Path:
    protected = directory / "protected"
    shutil.copyfile(original, protected)
    binary = Binary(protected, writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260827}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return protected


def benchmark_pair(original: Path, protected: Path | None = None) -> dict[str, object]:
    """Benchmark every configured analyzer and preserve unavailable evidence."""
    if not original.is_file():
        raise ValueError(f"original binary does not exist: {original}")
    with tempfile.TemporaryDirectory(prefix="r2morph-adversarial-") as directory:
        protected_path = protected or _protected_copy(original, Path(directory))
        tools = [_measure_tool(tool, original, protected_path) for tool in _EXPECTED_TOOLS]
        tools.append(
            {
                "tool": "custom",
                "status": "completed",
                "original": _binary_metric(original),
                "protected": _binary_metric(protected_path),
            }
        )
    return {"schema_version": 1, "original": original.name, "protected": protected_path.name, "tools": tools}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("--protected", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = benchmark_pair(args.original, args.protected)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
