from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier


def test_iterative_simplifier_preprocess_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        simplifier = IterativeSimplifier(binary=bin_obj)
        context = simplifier._analyze_binary()
        processed = simplifier._preprocess_binary(context)
        assert "obfuscation_patterns" in processed
        assert "vm_dispatchers" in processed
        assert "mba_expressions" in processed
