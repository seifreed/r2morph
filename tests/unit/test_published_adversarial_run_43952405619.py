"""Verifies the published adversarial run evidence and its open release gates."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "docs/protection-adversarial-run-2026-11-16-43952405619.json"
_REPORT = _ROOT / "docs/protection-adversarial-run-2026-11-16-43952405619.json.gz"
_RUN_ID = 43_952_405_619
_EXPECTED_SAMPLES = 362
_EXPECTED_PASSES = 22
_EXPECTED_PASS_RUNS = 7_964
_EXPECTED_ANALYZER_RUNS = 71_676
_COMPLETED_ANALYZER_RUNS = 55_220
_UNAVAILABLE_ANALYZER_RUNS = 16_456
_ZERO = 0
_CHUNK_BYTES = 1024 * 1024
_PATH_CONTEXT_BYTES = 256
_HOST_PATH = re.compile(rb"(?:/(?:Users|home|tmp|root|workspace|private/tmp)/|[A-Za-z]:\\Users\\)")


def _manifest() -> dict[str, object]:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _report_metadata() -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = _ZERO
    with gzip.open(_REPORT, "rb") as artifact:
        for chunk in iter(lambda: artifact.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
            byte_count += len(chunk)
    return digest.hexdigest(), byte_count


def test_published_adversarial_run_archive_matches_manifest() -> None:
    manifest = _manifest()
    archive = manifest["archive"]
    uncompressed_digest, uncompressed_bytes = _report_metadata()

    expect(
        archive["path"] == str(_REPORT.relative_to(_ROOT))
        and archive["sha256"] == _digest(_REPORT)
        and archive["uncompressed_sha256"] == uncompressed_digest
        and archive["uncompressed_bytes"] == uncompressed_bytes
    )


def test_published_adversarial_run_records_coverage_and_open_gates() -> None:
    manifest = _manifest()
    scope = manifest["scope"]
    results = manifest["results"]
    resistance = manifest["vm_resistance_smoke"]
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        manifest["workflow"]["run_id"] == _RUN_ID
        and manifest["workflow"]["conclusion"] == "success"
        and manifest["workflow"]["jobs"] == {"successful": 33, "failed": 0, "skipped": 0, "total": 33}
        and scope["sample_count"] == _EXPECTED_SAMPLES
        and scope["pass_count"] == _EXPECTED_PASSES
        and scope["expected_pass_runs"] == _EXPECTED_PASS_RUNS
        and scope["observed_pass_runs"] == _EXPECTED_PASS_RUNS
        and scope["expected_analyzer_runs"] == _EXPECTED_ANALYZER_RUNS
        and scope["observed_analyzer_runs"] == _EXPECTED_ANALYZER_RUNS
        and results["completed_analyzer_runs"] == _COMPLETED_ANALYZER_RUNS
        and results["unavailable_analyzer_runs"] == _UNAVAILABLE_ANALYZER_RUNS
        and results["analyzer_errors"] == _ZERO
        and results["missing_analyzer_runs"] == _ZERO
        and results["unavailable_runs_by_tool"]
        == {"binary-ninja": _EXPECTED_PASS_RUNS, "ida-pro": _EXPECTED_PASS_RUNS, "unicorn": 528}
        and resistance["human_adversarial_review"] == "pending-human-adversarial-review"
        and resistance["general_resistance_established"] is False
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_published_adversarial_run_contains_no_analyst_host_paths() -> None:
    trailing_bytes = b""
    with gzip.open(_REPORT, "rb") as artifact:
        for chunk in iter(lambda: artifact.read(_CHUNK_BYTES), b""):
            content = trailing_bytes + chunk
            if _HOST_PATH.search(content):
                expect(False)
            trailing_bytes = content[-_PATH_CONTEXT_BYTES:]

    expect(True)
