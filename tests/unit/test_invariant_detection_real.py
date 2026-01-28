from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.analysis.invariants import InvariantDetector, SemanticValidator


def test_invariant_detection_on_real_function():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        assert functions

        detector = InvariantDetector(bin_obj)
        invariants = detector.detect_all_invariants(functions[0].get("offset", 0))
        assert isinstance(invariants, list)

        validated = detector.verify_invariants(functions[0].get("offset", 0), invariants)
        assert isinstance(validated, list)


def test_semantic_validator_batch():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        assert functions

        addresses = [func.get("offset", 0) for func in functions[:2]]
        validator = SemanticValidator(bin_obj)
        invariants_map = {
            addr: validator.detector.detect_all_invariants(addr) for addr in addresses
        }

        result = validator.batch_validate(addresses, invariants_map)
        assert result["functions_validated"] == len(addresses)
        assert "all_valid" in result
