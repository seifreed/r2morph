"""
Pytest configuration and fixtures.

Test Markers:
- stable: Tests for stable mutations (nop, substitute, register)
- experimental: Tests for experimental mutations (expand, block, opaue, dead-code, cff)
- product_smoke: Product acceptance tests for CI
- slow: Tests that take longer than 10 seconds
"""

import os
import json
import subprocess
from pathlib import Path

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "stable: marks tests for stable mutation passes (nop, substitute, register)")
    config.addinivalue_line(
        "markers", "experimental: marks tests for experimental mutation passes (expand, block, opaque, dead-code, cff)"
    )
    config.addinivalue_line("markers", "product_smoke: marks product acceptance tests for CI")
    config.addinivalue_line("markers", "slow: marks tests that take longer than 10 seconds")


def pytest_collection_modifyitems(config, items):
    """Add marker to tests based on file location."""
    for item in items:
        # Auto-mark tests in product_smoke directory
        if "product_smoke" in str(item.fspath):
            item.add_marker(pytest.mark.product_smoke)

        # Auto-mark tests in integration directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Auto-mark tests in unit directory
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)


@pytest.fixture
def sample_binary(tmp_path):
    """
    Create a sample binary file for testing.

    Returns:
        Path to the temporary binary file
    """
    binary_file = tmp_path / "test_binary"
    binary_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    return binary_file


@pytest.fixture
def stable_elf_binary() -> Path:
    """
    Stable ELF x86_64 fixture used by product-smoke tests.
    """
    return Path(__file__).parent.parent / "dataset" / "elf_x86_64"


@pytest.fixture
def stable_runtime_corpus() -> list[dict[str, object]]:
    """
    Small runtime corpus for product validation.
    """
    corpus_path = Path(__file__).parent.parent / "dataset" / "runtime_corpus.json"
    return json.loads(corpus_path.read_text(encoding="utf-8"))


@pytest.fixture
def stable_runtime_corpus_path() -> Path:
    """
    Path to the canonical runtime corpus fixture used by product flows.
    """
    return Path(__file__).parent.parent / "dataset" / "runtime_corpus.json"


def _compile_c_binary(tmp_path: Path, name: str, source: str) -> Path:
    output = tmp_path / name
    source_path = tmp_path / f"{name}.c"
    source_path.write_text(source, encoding="utf-8")
    subprocess.run(
        ["gcc", "-O0", "-g", str(source_path), "-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    output.chmod(0o755)
    return output


def _find_cross_elf_toolchain() -> tuple[str, str] | None:
    clang_candidates = [
        "/opt/homebrew/opt/llvm/bin/clang",
        os.environ.get("CC", ""),
        "clang",
    ]
    lld_candidates = [
        "/opt/homebrew/bin/ld.lld",
        "ld.lld",
        "lld",
    ]

    clang = next((candidate for candidate in clang_candidates if candidate and Path(candidate).exists()), None)
    if clang is None:
        for candidate in clang_candidates:
            if (
                candidate
                and subprocess.run(["/usr/bin/env", "sh", "-c", f"command -v {candidate} >/dev/null 2>&1"]).returncode
                == 0
            ):
                clang = candidate
                break

    lld = next((candidate for candidate in lld_candidates if Path(candidate).exists()), None)
    if lld is None:
        for candidate in lld_candidates:
            if subprocess.run(["/usr/bin/env", "sh", "-c", f"command -v {candidate} >/dev/null 2>&1"]).returncode == 0:
                lld = candidate
                break

    if not clang or not lld:
        return None
    return clang, lld


def _compile_elf_x86_64_binary(tmp_path: Path, name: str, source: str) -> Path:
    toolchain = _find_cross_elf_toolchain()
    if toolchain is None:
        pytest.skip("ELF x86_64 cross-toolchain not available")

    clang, lld = toolchain
    asm_path = tmp_path / f"{name}.S"
    obj_path = tmp_path / f"{name}.o"
    output = tmp_path / name
    asm_path.write_text(source, encoding="utf-8")
    subprocess.run(
        [clang, "-target", "x86_64-unknown-linux-gnu", "-c", str(asm_path), "-o", str(obj_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [lld, "-o", str(output), str(obj_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    output.chmod(0o755)
    return output


@pytest.fixture
def runtime_binary_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Compile two real host binaries with deliberately different formatting."""
    original = _compile_c_binary(
        tmp_path,
        "runtime_original",
        """
#include <stdio.h>
int main(void) {
    puts("value:42");
    return 0;
}
""".strip(),
    )
    mutated = _compile_c_binary(
        tmp_path,
        "runtime_mutated",
        """
#include <stdio.h>
int main(void) {
    printf("value:42   \\n");
    return 0;
}
""".strip(),
    )
    return original, mutated


@pytest.fixture
def file_effect_binary_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Compile two real host binaries that write different side effects."""
    original = _compile_c_binary(
        tmp_path,
        "file_effect_original",
        """
#include <stdio.h>
int main(void) {
    FILE *fp = fopen("effect.txt", "w");
    if (!fp) return 1;
    fputs("A\\n", fp);
    fclose(fp);
    return 0;
}
""".strip(),
    )
    mutated = _compile_c_binary(
        tmp_path,
        "file_effect_mutated",
        """
#include <stdio.h>
int main(void) {
    FILE *fp = fopen("effect.txt", "w");
    if (!fp) return 1;
    fputs("B\\n", fp);
    fclose(fp);
    return 0;
}
""".strip(),
    )
    return original, mutated


@pytest.fixture
def patchable_runtime_binary(tmp_path: Path) -> Path:
    """Compile a host binary with a stable, patchable output string."""
    return _compile_c_binary(
        tmp_path,
        "runtime_patchable",
        """
#include <stdio.h>
int main(void) {
    puts("value:42");
    return 0;
}
""".strip(),
    )


@pytest.fixture
def exitcode_binary_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Compile two real host binaries that differ only in exit code."""
    original = _compile_c_binary(
        tmp_path,
        "exit_original",
        """
int main(void) {
    return 0;
}
""".strip(),
    )
    mutated = _compile_c_binary(
        tmp_path,
        "exit_mutated",
        """
int main(void) {
    return 7;
}
""".strip(),
    )
    return original, mutated


@pytest.fixture
def stderr_binary_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Compile two real host binaries that differ on stderr output."""
    original = _compile_c_binary(
        tmp_path,
        "stderr_original",
        """
#include <stdio.h>
int main(void) {
    fputs("error:A\\n", stderr);
    return 0;
}
""".strip(),
    )
    mutated = _compile_c_binary(
        tmp_path,
        "stderr_mutated",
        """
#include <stdio.h>
int main(void) {
    fputs("error:B\\n", stderr);
    return 0;
}
""".strip(),
    )
    return original, mutated


@pytest.fixture
def args_env_binary_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Compile two host binaries that differ only under argv/env-sensitive output."""
    original = _compile_c_binary(
        tmp_path,
        "args_env_original",
        """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char cwd[256];
    const char *mode = getenv("R2MORPH_MODE");
    if (!getcwd(cwd, sizeof(cwd))) return 2;
    printf("arg1=%s;mode=%s;cwd=%s\\n", argc > 1 ? argv[1] : "missing", mode ? mode : "unset", cwd);
    return 0;
}
""".strip(),
    )
    mutated = _compile_c_binary(
        tmp_path,
        "args_env_mutated",
        """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char cwd[256];
    const char *mode = getenv("R2MORPH_MODE");
    if (!getcwd(cwd, sizeof(cwd))) return 2;
    printf("arg1=%s;mode=%s-mutated;cwd=%s\\n", argc > 1 ? argv[1] : "missing", mode ? mode : "unset", cwd);
    return 0;
}
""".strip(),
    )
    return original, mutated


@pytest.fixture
def deterministic_nop_elf(tmp_path: Path) -> Path:
    """Small ELF with redundant instructions designed for NOP replacement."""
    return _compile_elf_x86_64_binary(
        tmp_path,
        "nop_fixture.elf",
        """
.global _start
.text
_start:
    mov %rax, %rax
    lea (%rcx), %rcx
    xchg %rdx, %rdx
    mov $60, %rax
    xor %rdi, %rdi
    syscall
""".strip(),
    )


@pytest.fixture
def deterministic_substitute_elf(tmp_path: Path) -> Path:
    """Small ELF with known instruction equivalence candidates."""
    return _compile_elf_x86_64_binary(
        tmp_path,
        "substitute_fixture.elf",
        """
.global _start
.text
_start:
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    mov $60, %rax
    xor %rdi, %rdi
    syscall
""".strip(),
    )


@pytest.fixture
def deterministic_register_elf(tmp_path: Path) -> Path:
    """Small ELF with caller-saved register substitution opportunities."""
    return _compile_elf_x86_64_binary(
        tmp_path,
        "register_fixture.elf",
        """
.global _start
.text
_start:
    mov $5, %eax
    add $2, %eax
    sub $1, %eax
    cmp $6, %eax
    jne done
    mov $6, %eax
done:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
""".strip(),
    )


@pytest.fixture
def deterministic_fail_elf(tmp_path: Path) -> Path:
    """Small ELF with no stable mutation candidates."""
    return _compile_elf_x86_64_binary(
        tmp_path,
        "fail_fixture.elf",
        """
.global _start
.text
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
""".strip(),
    )


@pytest.fixture
def deterministic_macho_sample(tmp_path: Path) -> Path:
    """Stable local Mach-O sample copied from dataset for format-level tests."""
    source = Path(__file__).parent.parent / "dataset" / "macho_arm64"
    if not source.exists():
        pytest.skip("Mach-O sample not available")
    target = tmp_path / "macho_arm64"
    target.write_bytes(source.read_bytes())
    target.chmod(0o755)
    return target


@pytest.fixture
def deterministic_pe_sample(tmp_path: Path) -> Path:
    """Stable local PE sample copied from dataset for format-level tests."""
    source = Path(__file__).parent.parent / "dataset" / "pe_x86_64.exe"
    if not source.exists():
        pytest.skip("PE sample not available")
    target = tmp_path / "pe_x86_64.exe"
    target.write_bytes(source.read_bytes())
    target.chmod(0o755)
    return target


@pytest.fixture
def sample_function_data():
    """
    Sample function data as returned by radare2.

    Returns:
        Dictionary with function metadata
    """
    return {
        "offset": 0x1000,
        "name": "sym.main",
        "size": 150,
        "callrefs": [0x2000, 0x3000],
        "type": "fcn",
    }


@pytest.fixture
def sample_instruction_data():
    """
    Sample instruction data as returned by radare2.

    Returns:
        Dictionary with instruction metadata
    """
    return {
        "offset": 0x1000,
        "disasm": "mov eax, 0x1",
        "bytes": "b801000000",
        "size": 5,
        "type": "mov",
    }


@pytest.fixture
def sample_functions_list():
    """
    Sample list of functions for testing.

    Returns:
        List of function dictionaries
    """
    return [
        {
            "offset": 0x1000,
            "name": "sym.main",
            "size": 150,
            "callrefs": [],
        },
        {
            "offset": 0x2000,
            "name": "sym.helper",
            "size": 80,
            "callrefs": [],
        },
        {
            "offset": 0x3000,
            "name": "sym.process",
            "size": 200,
            "callrefs": [0x1000],
        },
    ]
