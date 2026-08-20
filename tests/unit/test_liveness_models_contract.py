from r2morph.analysis.dataflow_models import Register
from r2morph.analysis.liveness_models import InstructionLiveness, InterferenceGraph, LiveRange
from tests.utils.assertions import expect


def test_liveness_models_contract() -> None:
    reg = Register("eax", 32)
    live_range = LiveRange(register=reg, start_address=0x1000, end_address=0x1010)
    liveness = InstructionLiveness(address=0x1000, instruction="mov eax, 1")
    graph = InterferenceGraph()
    graph.add_edge("eax", "ebx")

    expect(live_range.contains(0x1008))
    expect(liveness.to_dict()["instruction"] == "mov eax, 1")
    expect(graph.interfere("eax", "ebx"))
