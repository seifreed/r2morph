from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier
from tests.utils.assertions import expect


def test_iterative_simplifier_preprocess_real():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        simplifier = IterativeSimplifier(binary=bin_obj)
        context = simplifier._analyze_binary()
        processed = simplifier._preprocess_binary(context)
        expect(not ("obfuscation_patterns" not in processed))
        expect(not ("vm_dispatchers" not in processed))
        expect(not ("mba_expressions" not in processed))
