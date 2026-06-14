from types import SimpleNamespace

from r2morph.validation.semantic_invariant_models import InvariantSeverity
from r2morph.validation.semantic_models import ValidationResultStatus
from r2morph.validation.semantic_report_summary import build_semantic_report_summary


def test_build_semantic_report_summary_counts_results_and_violations() -> None:
    results = [
        SimpleNamespace(
            status=ValidationResultStatus.PASS,
            violations=[SimpleNamespace(severity=InvariantSeverity.CRITICAL)],
            region=SimpleNamespace(pass_name="nop"),
        ),
        SimpleNamespace(
            status=ValidationResultStatus.FAIL,
            violations=[],
            region=SimpleNamespace(pass_name="nop"),
        ),
        SimpleNamespace(
            status=ValidationResultStatus.ERROR,
            violations=[SimpleNamespace(severity=InvariantSeverity.ERROR)],
            region=SimpleNamespace(pass_name="flatten"),
        ),
        SimpleNamespace(
            status=ValidationResultStatus.SKIP,
            violations=[],
            region=SimpleNamespace(pass_name="flatten"),
        ),
    ]

    assert build_semantic_report_summary(results) == {
        "total_mutations": 4,
        "passed": 1,
        "failed": 1,
        "errors": 1,
        "skipped": 1,
        "total_violations": 2,
        "critical_violations": 1,
        "pass_rate": 0.25,
        "by_pass_type": {
            "nop": {"passed": 1, "failed": 1, "total": 2},
            "flatten": {"passed": 0, "failed": 0, "total": 2},
        },
        "overall_status": "fail",
    }


def test_build_semantic_report_summary_handles_empty_results() -> None:
    assert build_semantic_report_summary([]) == {
        "total_mutations": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "total_violations": 0,
        "critical_violations": 0,
        "pass_rate": 1.0,
        "by_pass_type": {},
        "overall_status": "pass",
    }
