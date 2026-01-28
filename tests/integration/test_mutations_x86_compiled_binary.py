import platform
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer
from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass


def _clang_available() -> bool:
    return shutil.which("clang") is not None


def _build_x86_binary(tmp_dir: Path) -> Path:
    source = tmp_dir / "x86_mutations.c"
    source.write_text(
        "#include <stdint.h>\n"
        "__attribute__((noinline)) int asm_ops(int x) {\n"
        "  int y = x;\n"
        "  __asm__ volatile(\n"
        "    \"mov %%eax, %%eax\\n\"\n"
        "    \"add $0, %%eax\\n\"\n"
        "    \"sub $0, %%eax\\n\"\n"
        "    \"or $0, %%eax\\n\"\n"
        "    \"mov $0, %%eax\\n\"\n"
        "    \"inc %%eax\\n\"\n"
        "    \"dec %%eax\\n\"\n"
        "    \"imul $3, %%eax, %%eax\\n\"\n"
        "    \"shl $1, %%eax\\n\"\n"
        "    \"cmp %%eax, %%eax\\n\"\n"
        "    \"test %%eax, %%eax\\n\"\n"
        "    \"nop\\n\"\n"
        "    \"nop\\n\"\n"
        "    \"nop\\n\"\n"
        "    :\n"
        "    : \"a\"(y)\n"
        "    : \"cc\"\n"
        "  );\n"
        "  return y;\n"
        "}\n"
        "__attribute__((noinline)) int branchy(int x) {\n"
        "  if (x & 1) { return x + 1; }\n"
        "  return x - 1;\n"
        "}\n"
        "int main(void) { return asm_ops(3) + branchy(2); }\n"
    )
    output = tmp_dir / "x86_mutations"
    subprocess.run(
        ["/usr/bin/clang", "-arch", "x86_64", "-O0", "-fno-inline", "-o", str(output), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    return output


@pytest.fixture(scope="module")
def x86_binary_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if platform.system() != "Darwin":
        pytest.skip("x86_64 Mach-O build only on macOS")
    if not _clang_available():
        pytest.skip("clang not available")

    tmp_dir = tmp_path_factory.mktemp("x86_mutations")
    return _build_x86_binary(tmp_dir)


def _copy_writable(tmp_path: Path, src: Path) -> Path:
    dst = tmp_path / src.name
    shutil.copy(src, dst)
    return dst


def test_x86_nop_insertion_and_substitution_real(x86_binary_path: Path, tmp_path: Path):
    random.seed(0)
    writable_path = _copy_writable(tmp_path, x86_binary_path)

    with Binary(writable_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")

        nop_pass = NopInsertionPass(
            config={"probability": 1.0, "max_nops_per_function": 5, "use_creative_nops": True}
        )
        nop_result = nop_pass.apply(bin_obj)

        sub_pass = InstructionSubstitutionPass(
            config={"probability": 1.0, "max_substitutions_per_function": 5, "force_different": True}
        )
        sub_result = sub_pass.apply(bin_obj)

    assert "mutations_applied" in nop_result
    assert "mutations_applied" in sub_result


def test_x86_instruction_expansion_and_register_substitution_real(
    x86_binary_path: Path, tmp_path: Path
):
    random.seed(1)
    writable_path = _copy_writable(tmp_path, x86_binary_path)

    with Binary(writable_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")

        exp_pass = InstructionExpansionPass(
            config={"probability": 1.0, "max_expansions_per_function": 10, "max_expansion_size": 4}
        )
        exp_result = exp_pass.apply(bin_obj)

        reg_pass = RegisterSubstitutionPass(
            config={"probability": 1.0, "max_substitutions_per_function": 2}
        )
        reg_result = reg_pass.apply(bin_obj)

    assert "mutations_applied" in exp_result
    assert "mutations_applied" in reg_result


def test_x86_block_reordering_real(x86_binary_path: Path, tmp_path: Path):
    random.seed(2)
    writable_path = _copy_writable(tmp_path, x86_binary_path)

    with Binary(writable_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        pass_obj = BlockReorderingPass(config={"probability": 1.0, "max_functions": 5})
        result = pass_obj.apply(bin_obj)

    assert "functions_processed" in result


def test_x86_opaque_predicates_and_control_flow_detection(
    x86_binary_path: Path, tmp_path: Path
):
    random.seed(3)
    writable_path = _copy_writable(tmp_path, x86_binary_path)

    with Binary(writable_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")

        op_pass = OpaquePredicatePass(config={"probability": 1.0, "max_predicates_per_function": 2})
        op_result = op_pass.apply(bin_obj)

        analyzer = ControlFlowAnalyzer(bin_obj)
        result = analyzer.analyze()
        custom = analyzer.detect_custom_virtualizer()
        meta = analyzer._detect_metamorphic_engine()

    assert "mutations_applied" in op_result
    assert isinstance(result.cff_detected, bool)
    assert isinstance(custom, dict)
    assert isinstance(meta, dict)
