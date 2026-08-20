from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.iterative_simplifier import (
    IterativeSimplifier,
    SimplificationPhase,
    SimplificationStrategy,
)
from tests.utils.assertions import expect


def test_iterative_simplifier_sequential():
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        simplifier = IterativeSimplifier(bin_obj)
        simplifier.max_iterations = 1
        simplifier.timeout = 10

        result = simplifier.simplify(strategy=SimplificationStrategy.CONSERVATIVE)

        expect(not (result.success is not True))
        expect(not (SimplificationPhase.ANALYSIS not in result.phases_completed))
        expect(not (SimplificationPhase.OPTIMIZATION not in result.phases_completed))
        expect(not (SimplificationPhase.VALIDATION not in result.phases_completed))


def test_iterative_simplifier_parallel_execution():
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        simplifier = IterativeSimplifier(bin_obj)
        simplifier.max_iterations = 1
        simplifier.timeout = 10
        simplifier.parallel_execution = True

        result = simplifier.simplify(strategy=SimplificationStrategy.ADAPTIVE)
        expect(not (result.success is not True))
