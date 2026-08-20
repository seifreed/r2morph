from r2morph.analysis.type_inference_convention_resolver import get_calling_convention
from tests.utils.assertions import expect


def test_type_inference_convention_resolver_contract() -> None:
    expect(get_calling_convention("x86_64", 64)["return_register"] == "rax")
    expect(get_calling_convention("mips", 32)["param_registers"] == [])
