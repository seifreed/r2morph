"""Pin multi-fixture VM resistance evidence to its source and report hash."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-vm-resistance-local-2026-11-15-f8586a1-32seed-10fixtures-summary.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_SOURCE_COMMIT = "f8586a1beb0068d53bcc9ebaf3009ce0e2e8e375"
_SUMMARY_REFERENCE = "docs/protection-vm-resistance-local-2026-11-15-f8586a1-32seed-10fixtures-summary.json"
_FIXTURE_COUNT = 10
_PROGRESSIVE_GROWTH_FIXTURE_COUNT = 7
_SEED_COUNT = 32
_TAMPER_PROBE_COUNT = 160
_ZERO = 0


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _report() -> dict[str, object]:
    summary = _json(_SUMMARY)
    return json.loads(gzip.decompress((_ROOT / summary["report"]["path"]).read_bytes()))


def test_published_vm_resistance_report_is_bound_to_source_and_hash() -> None:
    summary = _json(_SUMMARY)
    report = summary["report"]
    archive = _ROOT / report["path"]
    raw = gzip.decompress(archive.read_bytes())

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and hashlib.sha256(archive.read_bytes()).hexdigest() == report["sha256"]
        and hashlib.sha256(raw).hexdigest() == report["raw_sha256"]
    )


def test_published_vm_resistance_report_records_all_fixture_outcomes() -> None:
    measurement = _json(_SUMMARY)["measurement"]

    expect(
        measurement["fixture_count"] == _FIXTURE_COUNT
        and measurement["seed_count"] == _SEED_COUNT
        and measurement["cross_fixture_distinct_artifacts"] is True
        and measurement["semantic_parity"] is True
        and measurement["all_tamper_probes_diverged"] is True
        and measurement["tamper_probe_count"] == _TAMPER_PROBE_COUNT
        and measurement["handler_diversity_observed"] is True
        and measurement["progressive_growth_supported_fixture_count"] == _PROGRESSIVE_GROWTH_FIXTURE_COUNT
    )


def test_published_vm_resistance_raw_report_confirms_each_fixture() -> None:
    report = _report()
    fixtures = report["fixtures"]

    expect(
        len(fixtures) == _FIXTURE_COUNT
        and all(fixture["seed_campaign"]["semantic_parity"] is True for fixture in fixtures)
        and all(
            layer["all_tamper_probes_diverged"] is True
            for fixture in fixtures
            for layer in fixture["anti_tamper"].values()
        )
        and all(
            fixture["opcode_and_dispatcher_diversity"]["handler_report"]["cross_seed_exact_normalised_matches"] == _ZERO
            for fixture in fixtures
        )
    )


def test_published_vm_resistance_report_has_no_exact_handler_collisions() -> None:
    measurement = _json(_SUMMARY)["measurement"]

    expect(
        measurement["cross_seed_exact_handler_collisions_per_fixture"] == [_ZERO] * _FIXTURE_COUNT
        and measurement["within_seed_exact_handler_collisions_per_fixture"] == [_ZERO] * _FIXTURE_COUNT
    )


def test_published_vm_resistance_evidence_keeps_human_review_open() -> None:
    summary = _json(_SUMMARY)
    readiness = _json(_READINESS)
    criterion = readiness["criteria"]["published_resistance_results"]

    expect(
        summary["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and criterion["status"] == "open"
        and summary["report"]["path"] in criterion["evidence"]
        and _SUMMARY_REFERENCE in criterion["evidence"]
    )
