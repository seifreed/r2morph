from r2morph.devirtualization.iterative_simplifier_passes import (
    CFOSimplificationPass,
    MBASimplificationPass,
    VMDevirtualizationPass,
)


def test_iterative_simplifier_passes_contract() -> None:
    assert CFOSimplificationPass().get_name() == "CFO_Simplification"
    assert MBASimplificationPass().get_name() == "MBA_Simplification"
    assert VMDevirtualizationPass().get_name() == "VM_Devirtualization"
