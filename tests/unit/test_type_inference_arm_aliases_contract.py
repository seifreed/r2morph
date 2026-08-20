from r2morph.analysis.type_inference_arm_aliases import get_arm_register_aliases, propagate_arm_aliases
from tests.utils.assertions import expect


def test_type_inference_arm_aliases_contract() -> None:
    aliases = get_arm_register_aliases("arm64", 64)
    expect(aliases["x0"] == ["w0", "x0"])
    expect(aliases["sp"] == ["sp", "x31"])

    registers = {"x0": "ptr"}
    propagate_arm_aliases(registers, aliases)
    expect(registers["w0"] == "ptr")
