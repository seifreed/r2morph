from r2morph.analysis.type_inference_convention_resolver import get_calling_convention


def test_type_inference_convention_resolver_contract() -> None:
    assert get_calling_convention("x86_64", 64)["return_register"] == "rax"
    assert get_calling_convention("mips", 32)["param_registers"] == []
