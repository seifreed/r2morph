"""Shared constants for adversarial benchmark modules."""

from __future__ import annotations

import re
from pathlib import Path

from scripts.protection_maturity_baseline import (
    CORPUS_PASS_NAMES,
    EXTENDED_MATURITY_PASS_NAMES,
)

_COMMANDS = {"radare2": "r2", "objdump": "objdump", "ida-pro": "idat", "ghidra": "ghidra"}
_COMMAND_ENVIRONMENT = {"ida-pro": "IDA_HEADLESS", "ghidra": "GHIDRA_HEADLESS"}
_PYTHON_MODULES = {
    "angr": "angr",
    "binary-ninja": "binaryninja",
    "triton": "triton",
    "unicorn": "unicorn",
}
_BINARY_NINJA_PYTHON_PATH_ENV = "BINARY_NINJA_PYTHON_PATH"
_BINARY_NINJA_PYTHON_PATHS = (Path("/Applications/Binary Ninja.app/Contents/Resources/python"),)
_EXPECTED_TOOLS = ("radare2", "objdump", "angr", "binary-ninja", "unicorn", "triton", "ida-pro", "ghidra")
_DISASSEMBLY_LINE = re.compile(r"^\s*[0-9a-f]+:\s", re.IGNORECASE)
_COMMAND_TIMEOUT_SECONDS = 30
_GHIDRA_ANALYSIS_TIMEOUT_SECONDS = 60
_GHIDRA_PROCESS_TIMEOUT_SECONDS = _GHIDRA_ANALYSIS_TIMEOUT_SECONDS * 3
_IN_PROCESS_TOOL_TIMEOUT_SECONDS = 180
_IN_PROCESS_TOOLS = frozenset({"angr", "binary-ninja", "unicorn", "triton", "custom"})
_FULL_COVERAGE_PERCENT = 100.0
_PASS_STATUS_FIELDS = {"applied": "applied", "omitted": "omitted", "no-op": "no_op", "error": "errors"}
_GHIDRA_SCRIPT = Path(__file__).with_name("ghidra")
_GHIDRA_COUNT_PATTERN = re.compile(r"R2MORPH_FUNCTION_COUNT=(?:(?P<program>[^=\r\n]+)=)?(?P<count>\d+)")
_GHIDRA_DECOMPILER_PATTERN = re.compile(
    r"R2MORPH_DECOMPILER=(?P<program>[^=\r\n]+)=(?P<entrypoints>\d+)=(?P<lines>\d+)=(?P<bytes>\d+)"
)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_IDA_SCRIPT = Path(__file__).with_name("ida") / "count_functions.py"
_IDA_RESULT_SUFFIX = ".function-count"
_PF_EXECUTE = 1
_MAX_X86_INSTRUCTION_BYTES = 15
_TRITON_INSTRUCTION_BUDGET = 50_000
_ANGR_DECOMPILER_FUNCTION_LIMIT = 4
_ADVERSARIAL_ALL_PASS_NAMES = tuple(dict.fromkeys((*CORPUS_PASS_NAMES, *EXTENDED_MATURITY_PASS_NAMES)))
