import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass


def _copy_binary(tmp_path: Path, name: str) -> Path:
    src = Path("dataset/elf_x86_64")
    dst = tmp_path / name
    shutil.copy2(src, dst)
    return dst


def _run_pass(tmp_path: Path, pass_cls, name: str):
    binary_path = _copy_binary(tmp_path, name)
    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        mutation = pass_cls({"probability": 1.0})
        result = mutation.apply(bin_obj)
        assert isinstance(result, dict)
        return result


def test_control_flow_flattening_end_to_end(tmp_path: Path):
    result = _run_pass(tmp_path, ControlFlowFlatteningPass, "cff_bin")
    assert "mutations_applied" in result
    assert "functions_mutated" in result


def test_register_substitution_end_to_end(tmp_path: Path):
    result = _run_pass(tmp_path, RegisterSubstitutionPass, "regsub_bin")
    assert "mutations_applied" in result
    assert "functions_mutated" in result


def test_instruction_expansion_end_to_end(tmp_path: Path):
    result = _run_pass(tmp_path, InstructionExpansionPass, "expand_bin")
    assert "mutations_applied" in result
    assert "functions_mutated" in result


def test_dead_code_injection_end_to_end(tmp_path: Path):
    result = _run_pass(tmp_path, DeadCodeInjectionPass, "deadcode_bin")
    assert "mutations_applied" in result
    assert "functions_mutated" in result


def test_opaque_predicates_end_to_end(tmp_path: Path):
    result = _run_pass(tmp_path, OpaquePredicatePass, "opaque_bin")
    assert "mutations_applied" in result
    assert "functions_mutated" in result
