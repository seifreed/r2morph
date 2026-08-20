from r2morph.analysis.dataflow_models import Definition, Register, Use
from r2morph.analysis.defuse_models import DefWeb, UseWeb
from tests.utils.assertions import expect


def test_defuse_models_contract() -> None:
    reg = Register("eax", 32)
    defn = Definition(address=0x1000, register=reg)
    use = Use(address=0x1010, register=reg)

    def_web = DefWeb(definition=defn, uses=[use], register=reg)
    use_web = UseWeb(use=use, definitions=[defn], register=reg)

    expect(def_web.contains_address(0x1000))
    expect(use_web.is_unique())
    expect(def_web.to_dict()["register"] == "eax")
