from pathlib import Path

import pytest

from r2morph.analysis.invariants import InvariantDetector, SemanticValidator
from r2morph.core.binary import Binary


def _get_first_function_addr(bin_obj: Binary) -> int:
    funcs = bin_obj.get_functions()
    assert funcs
    func = funcs[0]
    return func.get("offset", func.get("addr", 0))


def test_invariants_and_validation_on_real_binary():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        func_addr = _get_first_function_addr(bin_obj)

        detector = InvariantDetector(bin_obj)
        invariants = detector.detect_all_invariants(func_addr)
        assert isinstance(invariants, list)

        violations = detector.verify_invariants(func_addr, invariants)
        assert violations == []

        validator = SemanticValidator(bin_obj)
        result = validator.validate_mutation(func_addr, invariants)
        assert result["valid"] is True

        none_result = validator.validate_mutation(func_addr, None)
        assert none_result["valid"] is True

        batch = validator.batch_validate([func_addr], {func_addr: invariants})
        assert batch["all_valid"] is True
