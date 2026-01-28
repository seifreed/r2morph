from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.analysis.invariants import InvariantDetector, SemanticValidator
from r2morph.core.binary import Binary


def test_invariant_detection_and_validation() -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    with Binary(source) as binary:
        binary.analyze()
        funcs = binary.get_functions()
        if not funcs:
            pytest.skip("No functions found")

        func_addr = funcs[0].get("offset", 0) or funcs[0].get("addr", 0)
        assert func_addr

        detector = InvariantDetector(binary)
        invs = detector.detect_all_invariants(func_addr)
        assert isinstance(invs, list)

        validator = SemanticValidator(binary)
        result = validator.validate_mutation(func_addr, invs)
        assert result["valid"] is True
