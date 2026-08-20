from r2morph.analysis.memory_flow_interprocedural import InterproceduralDataFlowAnalyzer
from tests.utils.assertions import expect


def test_memory_flow_interprocedural_contract() -> None:
    analyzer = InterproceduralDataFlowAnalyzer()
    result = analyzer.analyze_program([], {})

    expect(result["function_summaries"] == {})
    expect(result["call_graph"] == {})
    expect(result["propagated_values"] == {"parameter_bindings": {}, "value_flow": {}})
