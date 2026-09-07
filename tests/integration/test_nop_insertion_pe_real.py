import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect
from tests.utils.process import run_command


def test_nop_insertion_pe_x86_64_preserves_repaired_integrity(tmp_path: Path) -> None:
    compiler = shutil.which("x86_64-w64-mingw32-gcc")
    if compiler is None:
        pytest.skip("PE compiler not available")

    source = tmp_path / "nop_sample.c"
    source.write_text(
        "__attribute__((noinline)) int redundant(int value) {\n"
        '  __asm__ volatile("mov %%eax, %%eax\\n" : "+a"(value));\n'
        "  return value + 1;\n"
        "}\n"
        "int main(void) { return redundant(41) != 42; }\n"
    )
    binary_path = tmp_path / "nop_sample.exe"
    run_command([compiler, "-O0", "-fno-inline", "-o", str(binary_path), str(source)], check=True)

    handler = PEHandler(binary_path)
    expect(handler.fix_checksum())
    expect(handler.validate_integrity()[0])

    with Binary(binary_path, writable=True) as binary:
        binary.analyze("aaa")
        result = NopInsertionPass(
            {
                "probability": 1.0,
                "max_nops_per_function": 2,
                "use_creative_nops": False,
                "seed": 1337,
            }
        ).apply(binary)

    expect(result["mutations_applied"] > 0)
    expect(handler.fix_checksum())
    expect(handler.validate_integrity()[0])
