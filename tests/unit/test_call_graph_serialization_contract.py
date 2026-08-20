from r2morph.analysis.call_graph import CallGraph
from r2morph.analysis.call_graph_models import CallEdge, CallNode, CallType
from r2morph.analysis.call_graph_serialization import (
    call_graph_from_dict,
    call_graph_from_json,
    call_graph_to_dict,
    call_graph_to_dot,
    call_graph_to_json,
)
from tests.utils.assertions import expect


def test_call_graph_serialization_helpers_expose_expected_contract() -> None:
    cg = CallGraph()
    cg.add_node(CallNode(address=0x1000, name="main", size=16, call_type=CallType.DIRECT))
    cg.add_node(CallNode(address=0x2000, name="helper", size=8, call_type=CallType.DIRECT))
    cg.add_edge(CallEdge(caller=0x1000, callee=0x2000, call_type=CallType.DIRECT, call_site=0x1004))

    payload = call_graph_to_dict(cg)
    expect(payload["entry_points"] == ["0x1000"])
    expect(payload["leaf_functions"] == ["0x2000"])

    dot = call_graph_to_dot(cg)
    expect(not ('"0x1000"' not in dot))
    expect(not ('"0x1000" -> "0x2000"' not in dot))

    json_str = call_graph_to_json(cg)
    restored = call_graph_from_json(json_str)
    expect(restored.to_dict()["entry_points"] == ["0x1000"])

    from_dict = call_graph_from_dict(payload)
    expect(from_dict.to_dict()["leaf_functions"] == ["0x2000"])
