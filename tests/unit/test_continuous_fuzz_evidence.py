from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from tests.utils.assertions import expect

_REPOSITORY_ROOT = Path(__file__).parents[2]
_SUMMARY_PATH = _REPOSITORY_ROOT / "docs" / "continuous-fuzz-2026-11-19-44425946598-summary.json"


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def test_continuous_fuzz_evidence_raw_report_hashes_match_manifest() -> None:
    summary = _summary()
    platforms = summary["execution"]["platforms"]

    expect(
        all(
            sha256((_REPOSITORY_ROOT / "docs" / report["report"]).read_bytes()).hexdigest() == report["report_sha256"]
            for report in platforms.values()
        )
    )


def test_continuous_fuzz_evidence_reports_all_targets_without_failures() -> None:
    summary = _summary()
    execution = summary["execution"]
    targets = set(execution["targets"])
    platforms = execution["platforms"]

    expect(
        all(
            set(report["target_runs"]) == targets
            and set(report["target_runs"].values()) == {execution["cases_per_target_per_platform"]}
            and report["failure_count"] == 0
            and not report["failures"]
            for report in (
                json.loads((_REPOSITORY_ROOT / "docs" / platform["report"]).read_text())
                for platform in platforms.values()
            )
        )
    )


def test_continuous_fuzz_evidence_summary_totals_match_platform_reports() -> None:
    summary = _summary()
    platforms = summary["execution"]["platforms"].values()

    expect(
        summary["execution"]["total_target_runs"] == sum(platform["target_runs"] for platform in platforms)
        and summary["execution"]["total_failures"] == sum(platform["failure_count"] for platform in platforms)
    )
