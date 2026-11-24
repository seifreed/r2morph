"""Pin the current-source local release-contract check and its open limits."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/release-contract-check-local-2026-11-24-49279456.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_SOURCE_COMMIT = "492794568cc00afd8aec11630b3979014086d514"


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def test_local_release_contract_check_is_pinned_to_current_alpha_source() -> None:
    report = _load(_REPORT)

    expect(
        report["source_commit"] == _SOURCE_COMMIT
        and report["release_contract"]["status"] == "passed"
        and report["release_contract"]["package_version"] == "0.4.0-alpha.3"
        and report["readiness_contract_tests"]["passed"] == 158
        and report["readiness_contract_tests"]["failed"] == 0
        and report["readiness_contract_tests"]["skipped"] == 0
    )


def test_local_release_contract_report_preserves_open_stable_release_gates() -> None:
    report = _load(_REPORT)
    readiness = _load(_READINESS)
    open_criteria = sorted(
        name for name, criterion in readiness["criteria"].items() if criterion["status"] != "complete"
    )

    expect(
        report["one_zero_readiness"]["status"] == "blocked"
        and report["one_zero_readiness"]["blocking_criteria"] == open_criteria
        and "No stable release" in " ".join(report["scope_limits"])
    )
