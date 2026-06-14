"""Semantic-validation report summary helpers."""

from __future__ import annotations

from typing import Any

from r2morph.validation.semantic_invariant_models import InvariantSeverity
from r2morph.validation.semantic_models import ValidationResultStatus


def build_semantic_report_summary(results: list[Any]) -> dict[str, Any]:
    """Compute semantic-validation summary statistics."""
    passed = sum(1 for r in results if r.status == ValidationResultStatus.PASS)
    failed = sum(1 for r in results if r.status == ValidationResultStatus.FAIL)
    errors = sum(1 for r in results if r.status == ValidationResultStatus.ERROR)
    skipped = sum(1 for r in results if r.status == ValidationResultStatus.SKIP)

    total_violations = sum(len(r.violations) for r in results)
    critical_violations = sum(1 for r in results for v in r.violations if v.severity == InvariantSeverity.CRITICAL)

    by_pass: dict[str, dict[str, int]] = {}
    for result in results:
        pass_name = result.region.pass_name
        if pass_name not in by_pass:
            by_pass[pass_name] = {"passed": 0, "failed": 0, "total": 0}
        by_pass[pass_name]["total"] += 1
        if result.status == ValidationResultStatus.PASS:
            by_pass[pass_name]["passed"] += 1
        elif result.status == ValidationResultStatus.FAIL:
            by_pass[pass_name]["failed"] += 1

    return {
        "total_mutations": len(results),
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "total_violations": total_violations,
        "critical_violations": critical_violations,
        "pass_rate": passed / len(results) if results else 1.0,
        "by_pass_type": by_pass,
        "overall_status": "pass" if failed == 0 and errors == 0 else "fail",
    }

