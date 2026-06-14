from r2morph.analysis.type_inference_conventions import _AAPCS64_ARM64_CONVENTION, _SYSV_AMD64_CONVENTION


def test_type_inference_conventions_contract() -> None:
    assert _SYSV_AMD64_CONVENTION["return_register"] == "rax"
    assert _AAPCS64_ARM64_CONVENTION["param_registers"][0] == "x0"
