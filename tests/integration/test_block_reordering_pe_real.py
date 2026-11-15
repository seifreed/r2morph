"""Native execution regression for PE block reordering."""

import logging
import os
import platform
import shutil
from pathlib import Path
from typing import Any

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect
from tests.utils.process import run_command

_INPUTS = (-9, -2, -1, 0, 2, 5, 10, 18, 21)
_PE_EXECUTION_TIMEOUT_SECONDS = 60


def _pe_toolchain() -> tuple[str, str | None]:
    compiler = shutil.which("x86_64-w64-mingw32-gcc")
    is_windows = platform.system() == "Windows"
    runtime = None if is_windows else shutil.which("wine")
    if compiler is None or (not is_windows and runtime is None):
        pytest.skip("a PE compiler and a native Windows or Wine runtime are required")
    return compiler, runtime


def _build_pe_binary(directory: Path, compiler: str) -> Path:
    source = directory / "block_reordering.c"
    source.write_text(
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "__attribute__((noinline)) int branchy(int value) {\n"
        "  int result;\n"
        "  if (value < 0) result = value * 3 + 7;\n"
        "  else result = value / 2 - 5;\n"
        "  if (result == 4) result += 11;\n"
        "  else result -= 3;\n"
        "  return result;\n"
        "}\n"
        "int main(int argc, char **argv) {\n"
        "  if (argc != 10) return 125;\n"
        "  for (int index = 1; index < argc; ++index) {\n"
        '    printf("%d\\n", branchy((int)strtol(argv[index], 0, 10)));\n'
        "  }\n"
        "  return 0;\n"
        "}\n",
        encoding="ascii",
    )
    binary = directory / "block_reordering.exe"
    run_command([compiler, "-O0", "-fno-inline", "-o", str(binary), str(source)], check=True)
    return binary


def _run_pe(binary: Path, runtime: str | None, wine_prefix: Path) -> Any:
    arguments = [str(value) for value in _INPUTS]
    command = [str(binary), *arguments] if runtime is None else [runtime, str(binary), *arguments]
    env = None
    if runtime is not None:
        env = os.environ.copy()
        env["WINEPREFIX"] = str(wine_prefix)
    # Wine combines host diagnostics with stderr; compare the child's exit and stdout.
    return run_command(command, text=True, timeout=_PE_EXECUTION_TIMEOUT_SECONDS, env=env)


def test_pe_x86_64_block_reordering_preserves_native_observables(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="r2morph.mutations.block_reordering_relocation")
    compiler, runtime = _pe_toolchain()
    binary_path = _build_pe_binary(tmp_path, compiler)
    wine_prefix = tmp_path / "wine-prefix"
    original = _run_pe(binary_path, runtime, wine_prefix)
    expect(len(set(original.stdout.splitlines())) > 1, "PE fixture inputs did not exercise distinct outcomes")

    with Binary(binary_path, writable=True) as binary:
        binary.analyze("aa")
        result = BlockReorderingPass({"probability": 1.0, "max_functions": 100, "seed": 2}).apply(binary)

    handler = PEHandler(binary_path)
    reorder_diagnostics = [record.getMessage() for record in caplog.records if "branchy" in record.getMessage()]
    expect(
        result["mutations_applied"] > 0,
        f"PE x86-64 block reordering made no change: {result!r}; " f"reorder_diagnostics={reorder_diagnostics!r}",
    )
    expect(handler.fix_checksum(), "failed to repair the PE checksum after block reordering")
    expect(handler.validate_integrity()[0], "PE integrity validation failed after block reordering")
    mutated = _run_pe(binary_path, runtime, wine_prefix)

    expect(
        (mutated.returncode, mutated.stdout) == (original.returncode, original.stdout),
        "PE x86-64 block reordering changed return codes or stdout across the input set",
    )
