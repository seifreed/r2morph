from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier, SimplificationStrategy


def test_iterative_simplifier_sequential_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        simplifier = IterativeSimplifier(bin_obj)
        simplifier.max_iterations = 1
        simplifier.timeout = 5
        simplifier.parallel_execution = False
        result = simplifier.simplify(strategy=SimplificationStrategy.ADAPTIVE)

    assert result.success is True
    assert result.phases_completed


def test_iterative_simplifier_parallel_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        simplifier = IterativeSimplifier(bin_obj)
        simplifier.max_iterations = 1
        simplifier.timeout = 5
        simplifier.parallel_execution = True
        result = simplifier.simplify(strategy=SimplificationStrategy.CONSERVATIVE)

    assert result.success is True
    assert result.metrics.execution_time >= 0
