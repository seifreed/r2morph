from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier, SimplificationStrategy
from tests.utils.assertions import expect


def _load_binary(binary_path: Path) -> Binary:
    bin_obj = Binary(binary_path)
    bin_obj.open()
    bin_obj.analyze("aa")
    return bin_obj


def test_iterative_simplifier_sequential_real(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with _load_binary(binary_path) as bin_obj:
        simplifier = IterativeSimplifier(bin_obj)
        simplifier.parallel_execution = False

        result = simplifier.simplify(
            binary=bin_obj,
            strategy=SimplificationStrategy.CONSERVATIVE,
            max_iterations=1,
            timeout=30,
        )

    expect(not (result.success is not True))
    expect(result.phases_completed)
    expect(not (result.metrics.execution_time < 0))


def test_iterative_simplifier_parallel_real():
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with _load_binary(binary_path) as bin_obj:
        simplifier = IterativeSimplifier(bin_obj)
        simplifier.parallel_execution = True

        result = simplifier.simplify(
            binary=bin_obj,
            strategy=SimplificationStrategy.ADAPTIVE,
            max_iterations=1,
            timeout=30,
        )

    expect(not (result.success is not True))
    expect(
        not (
            result.strategy_used
            not in {
                SimplificationStrategy.ADAPTIVE,
                SimplificationStrategy.CONSERVATIVE,
                SimplificationStrategy.AGGRESSIVE,
                SimplificationStrategy.TARGETED,
            }
        )
    )
