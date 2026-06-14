from r2morph.analysis.type_inference_arm_aliases import get_arm_register_aliases, propagate_arm_aliases


def test_type_inference_arm_aliases_contract() -> None:
    aliases = get_arm_register_aliases("arm64", 64)
    assert aliases["x0"] == ["w0", "x0"]
    assert aliases["sp"] == ["sp", "x31"]

    registers = {"x0": "ptr"}
    propagate_arm_aliases(registers, aliases)
    assert registers["w0"] == "ptr"
