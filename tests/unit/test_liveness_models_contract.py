from r2morph.analysis.dataflow_models import Register
from r2morph.analysis.liveness_models import InstructionLiveness, InterferenceGraph, LiveRange


def test_liveness_models_contract() -> None:
    reg = Register("eax", 32)
    live_range = LiveRange(register=reg, start_address=0x1000, end_address=0x1010)
    liveness = InstructionLiveness(address=0x1000, instruction="mov eax, 1")
    graph = InterferenceGraph()
    graph.add_edge("eax", "ebx")

    assert live_range.contains(0x1008)
    assert liveness.to_dict()["instruction"] == "mov eax, 1"
    assert graph.interfere("eax", "ebx")
