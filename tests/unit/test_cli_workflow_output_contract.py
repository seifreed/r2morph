from __future__ import annotations

import pytest
import typer

from r2morph.cli_workflow_output import GateOutputOptions, evaluate_and_write_gates, print_mutation_summary
from tests.utils.assertions import expect


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
    expect(not ("Mutation Engine Results" not in captured.out))
    expect(not ("Binary saved to:" not in captured.out))


def test_evaluate_and_write_gates_writes_json(tmp_path) -> None:
    report_path = tmp_path / "report.json"
    evaluate_and_write_gates(
        {
            "summary": {"symbolic_severity_by_pass": []},
            "input": {"path": ""},
            "mutations": [],
            "validation": {"results": []},
        },
        GateOutputOptions(report_path, None, None, None),
    )
    expect(report_path.exists())


def test_evaluate_and_write_gates_rejects_min_severity(tmp_path) -> None:
    with pytest.raises(typer.Exit):
        evaluate_and_write_gates(
            {
                "summary": {"symbolic_severity_by_pass": []},
                "input": {"path": ""},
                "mutations": [],
                "validation": {"results": []},
            },
            GateOutputOptions(tmp_path / "report.json", "mismatch", 0, None),
        )
