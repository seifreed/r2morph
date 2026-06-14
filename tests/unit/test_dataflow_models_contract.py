from r2morph.analysis.dataflow_models import DataFlowDirection, DataFlowResult, Definition, DefUseChain, Register, Use


def test_dataflow_models_contract() -> None:
    reg = Register("eax", 32)
    defn = Definition(address=0x1000, register=reg, instruction="mov eax, 1")
    use = Use(address=0x1010, register=reg)
    chain = DefUseChain(definition=defn, register=reg)
    chain.add_use(use)

    result = DataFlowResult()
    result.def_use_chains.append(chain)

    assert DataFlowDirection.FORWARD.value == "forward"
    assert reg.aliases()
    assert result.get_def_use_chain(reg) == chain
