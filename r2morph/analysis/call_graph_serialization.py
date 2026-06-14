from __future__ import annotations

from typing import Any

from r2morph.analysis.call_graph_models import CallEdge, CallNode, CallType


def call_graph_to_dict(call_graph: Any) -> dict[str, Any]:
    return {
        "nodes": {f"0x{addr:x}": node.to_dict() for addr, node in call_graph.nodes.items()},
        "edges": [edge.to_dict() for edge in call_graph.edges],
        "entry_points": [f"0x{addr:x}" for addr in call_graph.get_entry_points()],
        "leaf_functions": [f"0x{addr:x}" for addr in call_graph.get_leaf_functions()],
        "recursive_functions": [f"0x{addr:x}" for addr in call_graph.find_recursive_functions()],
        "recursive_chains": [[f"0x{addr:x}" for addr in chain] for chain in call_graph._recursive_chains],
        "strongly_connected_components": [
            [f"0x{addr:x}" for addr in scc] for scc in call_graph.find_strongly_connected_components()
        ],
        "statistics": {
            "total_functions": len(call_graph.nodes),
            "total_calls": len(call_graph.edges),
            "entry_points": len(call_graph.get_entry_points()),
            "leaf_functions": len(call_graph.get_leaf_functions()),
            "recursive_functions": len(call_graph.find_recursive_functions()),
            "strongly_connected_components": len(call_graph._strongly_connected),
        },
    }


def call_graph_to_dot(call_graph: Any) -> str:
    lines = [
        "digraph CallGraph {",
        "  node [shape=box];",
        "  rankdir=TB;",
        "",
    ]

    for addr, node in call_graph.nodes.items():
        label = f"{node.name}\\n0x{addr:x}" if node.name else f"0x{addr:x}"
        color = "red" if node.is_recursive else "lightblue"
        if addr in call_graph.get_entry_points():
            color = "green"
        elif addr in call_graph.get_leaf_functions():
            color = "yellow"
        lines.append(f'  "0x{addr:x}" [label="{label}", style=filled, fillcolor={color}];')

    lines.append("")

    for edge in call_graph.edges:
        style = "dashed" if edge.call_type == CallType.INDIRECT else "solid"
        label = edge.call_type.value
        lines.append(f'  "0x{edge.caller:x}" -> "0x{edge.callee:x}" [style={style}, label="{label}"];')

    lines.append("}")
    return "\n".join(lines)


def call_graph_to_json(call_graph: Any) -> str:
    import json

    return json.dumps(call_graph_to_dict(call_graph), indent=2)


def call_graph_from_dict(data: dict[str, Any]) -> Any:
    from r2morph.analysis.call_graph import CallGraph

    cg = CallGraph()
    cg.entry_points = [int(ep, 16) for ep in data.get("entry_points", [])]

    for addr_str, node_data in data.get("nodes", {}).items():
        addr = int(addr_str, 16)
        node = CallNode(
            address=addr,
            name=node_data.get("name", ""),
            size=node_data.get("size", 0),
            call_type=CallType(node_data.get("call_type", "direct")),
            callers=[int(c, 16) for c in node_data.get("callers", [])],
            callees=[int(c, 16) for c in node_data.get("callees", [])],
            is_recursive=node_data.get("is_recursive", False),
            recursion_depth=node_data.get("recursion_depth", 0),
            metadata=node_data.get("metadata", {}),
        )
        cg.add_node(node)

    for edge_data in data.get("edges", []):
        edge = CallEdge(
            caller=int(edge_data["caller"], 16),
            callee=int(edge_data["callee"], 16),
            call_type=CallType(edge_data.get("call_type", "direct")),
            call_site=int(edge_data.get("call_site", "0x0"), 16),
            is_tail_call=edge_data.get("is_tail_call", False),
        )
        cg.add_edge(edge)

    for chain in data.get("recursive_chains", []):
        cg._recursive_chains.append([int(addr, 16) for addr in chain])

    for scc in data.get("strongly_connected_components", []):
        cg._strongly_connected.append({int(addr, 16) for addr in scc})

    return cg


def call_graph_from_json(json_str: str) -> Any:
    import json

    return call_graph_from_dict(json.loads(json_str))
