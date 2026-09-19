from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from scripts.protection_maturity_baseline import _GENERATED_CORPUS_SOURCES, _GENERATED_UNREACHABLE_PADDING
from tests.utils.assertions import expect
from tests.utils.process import run_command


def test_opaque_predicates_apply_real(tmp_path: Path) -> None:
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(binary_path.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        pass_obj = OpaquePredicatePass(config={"max_predicates_per_function": 1, "probability": 1.0})
        result = pass_obj.apply(binary)

    expect(not ("mutations_applied" not in result))
    expect(not ("functions_mutated" not in result))
    expect(not (result["mutations_applied"] < 0))


def test_opaque_predicates_preserve_varargs_stack_state(tmp_path: Path) -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("the generated ELF ABI regression fixture requires Linux")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("gcc not available for compiling the ABI regression fixture")

    source_path = tmp_path / "generated_abi.c"
    binary_path = tmp_path / "generated_abi"
    source_path.write_text(
        f"{_GENERATED_UNREACHABLE_PADDING}\n{_GENERATED_CORPUS_SOURCES['generated_abi']}",
        encoding="utf-8",
    )
    run_command(
        [
            compiler,
            "-O1",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            str(source_path),
            "-o",
            str(binary_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    binary_path.chmod(0o700)
    baseline = run_command([str(binary_path)], check=False, capture_output=True).returncode

    with Binary(binary_path, writable=True) as binary:
        result = OpaquePredicatePass(
            config={"max_predicates_per_function": 3, "probability": 1.0, "seed": 20260901}
        ).apply(binary)

    mutated = run_command([str(binary_path)], check=False, capture_output=True).returncode
    expect(result["mutations_applied"] == 0)
    expect(mutated == baseline)
