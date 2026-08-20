from r2morph.analysis.call_graph_models import CallEdge, CallNode, CallType, RecursionType
from tests.utils.assertions import expect


def test_call_graph_models_round_trip() -> None:
    node = CallNode(address=0x1000, name="main")
    edge = CallEdge(caller=0x1000, callee=0x2000, call_type=CallType.DIRECT)

    expect(node.to_dict()["address"] == "0x1000")
    expect(edge.to_dict()["call_type"] == "direct")
    expect(CallType.TAIL.value == "tail")
    expect(RecursionType.MUTUAL.value == "mutual")
