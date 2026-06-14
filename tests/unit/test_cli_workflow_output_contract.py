from __future__ import annotations

import pytest

from r2morph.cli_workflow_output import evaluate_and_write_gates, print_mutation_summary


def test_print_mutation_summary_handles_basic_result(tmp_path, capsys) -> None:
    print_mutation_summary(
        {
            "validation": {"all_passed": True, "total_issues": 0},
            "total_mutations": 1,
            "passes_run": 1,
            "rolled_back_passes": 0,
            "discarded_mutations": 0,
            "pass_results": {},
        },
        tmp_path / "out.bin",
    )
    captured = capsys.readouterr()
    assert "Mutation Engine Results" in captured.out
    assert "Binary saved to:" in captured.out


def test_evaluate_and_write_gates_writes_json(tmp_path) -> None:
    report_path = tmp_path / "report.json"
    evaluate_and_write_gates(
        report_payload={"summary": {"symbolic_severity_by_pass": []}, "input": {"path": ""}, "mutations": [], "validation": {"results": []}},
        report_path=report_path,
        min_severity=None,
        min_severity_rank=None,
        pass_severity_requirements=None,
        report_format="json",
    )
    assert report_path.exists()


def test_evaluate_and_write_gates_rejects_min_severity(tmp_path) -> None:
    with pytest.raises(SystemExit):
        evaluate_and_write_gates(
            report_payload={"summary": {"symbolic_severity_by_pass": []}, "input": {"path": ""}, "mutations": [], "validation": {"results": []}},
            report_path=tmp_path / "report.json",
            min_severity="mismatch",
            min_severity_rank=0,
            pass_severity_requirements=None,
            report_format="json",
        )
