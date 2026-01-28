import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer


def _clang_available() -> bool:
    return shutil.which("clang") is not None


def _build_pattern_binary(tmp_dir: Path) -> Path:
    source = tmp_dir / "control_flow_patterns.c"
    source.write_text(
        "#include <stdint.h>\n"
        "__attribute__((noinline)) int opaque_predicate(int x) {\n"
        "  int y = x;\n"
        "  __asm__ volatile(\n"
        "    \"cmp %%eax, %%eax\\n\"\n"
        "    \"jne 1f\\n\"\n"
        "    \"nop\\n\"\n"
        "    \"1:\\n\"\n"
        "    :\n"
        "    : \"a\"(y)\n"
        "    : \"cc\"\n"
        "  );\n"
        "  return y;\n"
        "}\n"
        "__attribute__((noinline)) int mba_mix(int x, int y) {\n"
        "  int r = x + y;\n"
        "  __asm__ volatile(\n"
        "    \"and %%eax, %%ebx\\n\"\n"
        "    \"or %%eax, %%ebx\\n\"\n"
        "    \"xor %%eax, %%ebx\\n\"\n"
        "    \"not %%eax\\n\"\n"
        "    \"and %%eax, %%ebx\\n\"\n"
        "    \"or %%eax, %%ebx\\n\"\n"
        "    \"add %%eax, %%ebx\\n\"\n"
        "    \"sub %%eax, %%ebx\\n\"\n"
        "    \"imul %%eax, %%ebx\\n\"\n"
        "    \"add %%eax, %%ebx\\n\"\n"
        "    \"sub %%eax, %%ebx\\n\"\n"
        "    \"add %%eax, %%ebx\\n\"\n"
        "    :\n"
        "    : \"a\"(x), \"b\"(y)\n"
        "    : \"cc\"\n"
        "  );\n"
        "  return r;\n"
        "}\n"
        "__attribute__((noinline)) void dispatcher_jump(void *ptr) {\n"
        "  __asm__ volatile(\n"
        "    \".intel_syntax noprefix\\n\"\n"
        "    \"jmp [rax]\\n\"\n"
        "    \".att_syntax\\n\"\n"
        "    :\n"
        "    : \"a\"(ptr)\n"
        "    : \"memory\"\n"
        "  );\n"
        "}\n"
        "__attribute__((noinline)) void vm_like(void *ptr) {\n"
        "  __asm__ volatile(\n"
        "    \".intel_syntax noprefix\\n\"\n"
        "    \"jmp [rax]\\n\"\n"
        "    \"jmp [rax]\\n\"\n"
        "    \"jmp [rax]\\n\"\n"
        "    \"jmp [rax]\\n\"\n"
        "    \"jmp [rax]\\n\"\n"
        "    \".att_syntax\\n\"\n"
        "    :\n"
        "    : \"a\"(ptr)\n"
        "    : \"memory\"\n"
        "  );\n"
        "}\n"
        "__attribute__((noinline)) void metamorphic_sample(int x) {\n"
        "  __asm__ volatile(\n"
        "    \"mov %%eax, %%eax\\n\"\n"
        "    \"mov %%eax, %%eax\\n\"\n"
        "    \"add $0, %%eax\\n\"\n"
        "    \"sub $0, %%eax\\n\"\n"
        "    \"xor $0, %%eax\\n\"\n"
        "    \"nop\\n\"\n"
        "    \"nop\\n\"\n"
        "    :\n"
        "    : \"a\"(x)\n"
        "    : \"cc\"\n"
        "  );\n"
        "}\n"
        "__attribute__((noinline)) void vm_pattern_blob(void) {\n"
        "  __asm__ volatile(\n"
        "    \".byte 0xff, 0x24, 0x85\\n\"\n"
        "    \".byte 0xff, 0x24, 0x95\\n\"\n"
        "    :\n"
        "    :\n"
        "    :\n"
        "  );\n"
        "}\n"
        "int main(void) {\n"
        "  int a = opaque_predicate(1);\n"
        "  int b = mba_mix(2, 3);\n"
        "  dispatcher_jump((void *)0);\n"
        "  vm_like((void *)0);\n"
        "  metamorphic_sample(a + b);\n"
        "  vm_pattern_blob();\n"
        "  return a + b;\n"
        "}\n"
    )

    output = tmp_dir / "control_flow_patterns"
    subprocess.run(
        [
            "/usr/bin/clang",
            "-arch",
            "x86_64",
            "-O0",
            "-fno-inline",
            "-o",
            str(output),
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return output


def _find_function_offset(binary: Binary, name_hint: str) -> int:
    for func in binary.get_functions():
        name = func.get("name", "")
        if name_hint in name:
            return func.get("offset") or func.get("addr") or 0
    return 0


@pytest.fixture(scope="module")
def pattern_binary_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if platform.system() != "Darwin":
        pytest.skip("x86_64 Mach-O build only on macOS")
    if not _clang_available():
        pytest.skip("clang not available")

    tmp_dir = tmp_path_factory.mktemp("control_flow_patterns")
    return _build_pattern_binary(tmp_dir)


def test_control_flow_detector_finds_opaque_and_mba(pattern_binary_path: Path):
    with Binary(pattern_binary_path) as bin_obj:
        bin_obj.analyze("aaa")
        analyzer = ControlFlowAnalyzer(bin_obj)

        assert analyzer._detect_opaque_predicates() >= 1
        assert analyzer._detect_mba_patterns() >= 1


def test_control_flow_detector_dispatcher_pattern(pattern_binary_path: Path):
    with Binary(pattern_binary_path) as bin_obj:
        bin_obj.analyze("aaa")
        analyzer = ControlFlowAnalyzer(bin_obj)

        dispatcher_addr = _find_function_offset(bin_obj, "dispatcher_jump")
        assert dispatcher_addr != 0

        blocks = bin_obj.get_basic_blocks(dispatcher_addr)
        assert analyzer._check_dispatcher_pattern(blocks) is True


def test_control_flow_detector_virtualization_and_metamorphic(pattern_binary_path: Path):
    with Binary(pattern_binary_path) as bin_obj:
        bin_obj.analyze("aaa")
        analyzer = ControlFlowAnalyzer(bin_obj)

        vm_result = analyzer._detect_virtualization()
        assert vm_result["handler_count"] >= 1
        assert vm_result["confidence"] > 0.0

        meta_result = analyzer._detect_metamorphic_engine()
        assert meta_result["polymorphic_ratio"] >= 0.0
        assert meta_result["confidence"] >= 0.0

        custom_vm = analyzer.detect_custom_virtualizer()
        assert "detected" in custom_vm
        assert "confidence" in custom_vm
        assert "vm_type" in custom_vm
