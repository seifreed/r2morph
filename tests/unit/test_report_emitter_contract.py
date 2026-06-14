from __future__ import annotations

from pathlib import Path

import pytest
import typer

from r2morph.reporting import report_emitter


def test_report_emitter_severity_and_result_checks_delegate() -> None:
    assert report_emitter.severity_threshold_met([{"severity": "mismatch"}], 0) is True
    assert report_emitter.report_view_has_results(
        mutation_count=0,
        only_failed_gates=False,
        failed_gates=False,
        pass_count=1,
    ) is True


def test_report_emitter_gate_failure_count_delegates() -> None:
    assert report_emitter.gate_failure_result_count({"require_pass_severity_failure_count": 2}) == 2


def test_emit_report_payload_writes_output(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    report_emitter.emit_report_payload(
        filtered_payload={"summary": {"ok": True}},
        output=output,
        summary_only=True,
    )

    assert output.exists()


def test_enforce_report_requirements_raises_when_empty() -> None:
    with pytest.raises(typer.Exit):
        report_emitter.enforce_report_requirements(
            require_results=True,
            severity_rows=[],
            min_severity_rank=None,
            mutation_count=0,
            only_failed_gates=False,
            failed_gates=False,
            gate_failure_count=None,
            only_risky_passes=False,
            risky_pass_count=0,
            pass_count=0,
        )
