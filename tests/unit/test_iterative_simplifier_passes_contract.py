from r2morph.devirtualization.iterative_simplifier_passes import (
    CFOSimplificationPass,
    MBASimplificationPass,
    VMDevirtualizationPass,
)
from tests.utils.assertions import expect


def test_iterative_simplifier_passes_contract() -> None:
    expect(CFOSimplificationPass().get_name() == "CFO_Simplification")
    expect(MBASimplificationPass().get_name() == "MBA_Simplification")
    expect(VMDevirtualizationPass().get_name() == "VM_Devirtualization")
