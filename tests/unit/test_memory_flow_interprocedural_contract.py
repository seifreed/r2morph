from r2morph.analysis.memory_flow_interprocedural import InterproceduralDataFlowAnalyzer


def test_memory_flow_interprocedural_contract() -> None:
    analyzer = InterproceduralDataFlowAnalyzer()
    result = analyzer.analyze_program([], {})

    assert result["function_summaries"] == {}
    assert result["call_graph"] == {}
    assert result["propagated_values"] == {"parameter_bindings": {}, "value_flow": {}}
