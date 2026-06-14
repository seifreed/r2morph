from r2morph.analysis.ssa_models import PhiFunction, SSABlock, SSAVariable


def test_ssa_models_contract() -> None:
    variable = SSAVariable(base_name="eax", version=2)
    phi = PhiFunction(result=variable, operands=[SSAVariable(base_name="eax", version=0)], block_address=0x1000)
    block = SSABlock(address=0x1000, phi_functions=[phi], definitions={"eax": variable})

    assert repr(variable) == "eax_2"
    assert variable == SSAVariable(base_name="eax", version=2)
    assert block.to_dict()["address"] == "0x1000"
    assert block.to_dict()["phi_functions"][0]["result"] == "eax_2"
