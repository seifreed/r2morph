from r2morph.reporting.report_orchestrator_context import build_report_flow_context


def test_report_orchestrator_context_contract() -> None:
    ctx = build_report_flow_context(
        payload={"mode": "test"},
        summary={"total": 1},
        filtered_summary={"kept": 1},
        mutations=[{"name": "noop"}],
        pass_results={"noop": {"passed": True}},
        pass_support={"noop": {"support": 1}},
        symbolic_state={"enabled": False},
        only_mismatches=True,
        only_status="warning",
        min_severity="low",
        summary_only=True,
        require_results=True,
    )

    assert ctx.data.payload["mode"] == "test"
    assert ctx.filters.only_mismatches is True
    assert ctx.filters.only_status == "warning"
    assert ctx.severity.min_severity == "low"
    assert ctx.output.summary_only is True
