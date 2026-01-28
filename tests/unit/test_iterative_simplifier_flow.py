from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.iterative_simplifier import (
    IterativeSimplifier,
    SimplificationStrategy,
    SimplificationPhase,
)


def test_iterative_simplifier_sequential():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        simplifier = IterativeSimplifier(bin_obj)
        simplifier.max_iterations = 1
        simplifier.timeout = 10

        result = simplifier.simplify(strategy=SimplificationStrategy.CONSERVATIVE)

        assert result.success is True
        assert SimplificationPhase.ANALYSIS in result.phases_completed
        assert SimplificationPhase.OPTIMIZATION in result.phases_completed
        assert SimplificationPhase.VALIDATION in result.phases_completed


def test_iterative_simplifier_parallel_execution():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        simplifier = IterativeSimplifier(bin_obj)
        simplifier.max_iterations = 1
        simplifier.timeout = 10
        simplifier.parallel_execution = True

        result = simplifier.simplify(strategy=SimplificationStrategy.ADAPTIVE)
        assert result.success is True
