from r2morph.analysis.call_graph_models import CallEdge, CallNode, CallType, RecursionType


def test_call_graph_models_round_trip() -> None:
    node = CallNode(address=0x1000, name="main")
    edge = CallEdge(caller=0x1000, callee=0x2000, call_type=CallType.DIRECT)

    assert node.to_dict()["address"] == "0x1000"
    assert edge.to_dict()["call_type"] == "direct"
    assert CallType.TAIL.value == "tail"
    assert RecursionType.MUTUAL.value == "mutual"
