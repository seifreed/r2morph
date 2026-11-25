"""Regression tests for collecting flat and per-artifact evidence layouts."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.differential_evidence import require_evidence_files
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_COLLECTOR_CALLS = 4


def test_require_evidence_files_accepts_single_flat_artifact(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    report = evidence / "report.xml"
    report.write_text("<testsuite />", encoding="utf-8")

    expect(require_evidence_files(evidence, 1) == [report])


def test_require_evidence_files_accepts_multiple_artifact_directories(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    report_paths = []
    for shard in range(2):
        artifact = evidence / f"artifact-{shard}"
        artifact.mkdir(parents=True)
        report = artifact / "report.xml"
        report.write_text("<testsuite />", encoding="utf-8")
        report_paths.append(report)

    expect(require_evidence_files(evidence, 2) == report_paths)


def test_require_evidence_files_rejects_missing_or_extra_files(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "report.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="expected 2 evidence files"):
        require_evidence_files(evidence, 2)


def test_differential_workflow_uses_the_tested_evidence_collector() -> None:
    workflow = (_ROOT / ".github/workflows/differential-corpus.yml").read_text(encoding="utf-8")

    expect(
        "from scripts.differential_evidence import require_evidence_files" in workflow
        and workflow.count("require_evidence_files(") == _WORKFLOW_COLLECTOR_CALLS
        and 'Path("differential-reports").glob("*/differential-corpus-*.json")' not in workflow
    )
