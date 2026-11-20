"""Pin bounded local VM resistance evidence and its known limitations."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-vm-resistance-local-2026-11-14-32seed-10fixtures-summary.json"
_ARCHIVE = _ROOT / "docs/protection-vm-resistance-local-2026-11-14-32seed-10fixtures.json.gz"
_HANDLERS = _ROOT / "docs/protection-vm-handler-diversity-local-2026-11-14-100seeds.json"
_CORRECTION = "docs/vm-resistance-metric-correction-2026-11-20.json"
_FIXTURE_COUNT = 10
_SEED_COUNT = 32
_HANDLER_SEED_COUNT = 100
_HANDLER_REPORT_SCHEMA_VERSION = 3
_HANDLER_COLLISION_COUNT = 54
_WITHIN_SEED_HANDLER_COLLISION_COUNT = 0
_HANDLER_COUNT_PER_SEED = 255
_LARGEST_HANDLER_CLUSTER = 2
_PROGRESSIVE_GROWTH_FIXTURE_COUNT = 7


def _report(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_local_vm_resistance_archive_matches_published_hashes() -> None:
    summary = _report(_SUMMARY)
    artifact = summary["artifacts"]["campaign"]
    compressed = _ARCHIVE.read_bytes()
    raw = gzip.decompress(compressed)

    expect(
        artifact["sha256"] == hashlib.sha256(compressed).hexdigest()
        and artifact["size_bytes"] == len(compressed)
        and artifact["uncompressed_sha256"] == hashlib.sha256(raw).hexdigest()
        and artifact["uncompressed_size_bytes"] == len(raw)
    )


def test_local_vm_resistance_report_records_parity_and_open_limitations() -> None:
    summary = _report(_SUMMARY)
    measurement = summary["measurement"]
    readiness = _report(_ROOT / "docs/one-zero-readiness.json")

    expect(
        summary["campaign"]["fixture_count"] == _FIXTURE_COUNT
        and summary["campaign"]["seed_count"] == _SEED_COUNT
        and measurement["semantic_parity"] is True
        and measurement["handler_diversity_observed"] is False
        and measurement["progressive_growth_supported_fixture_count"] == _PROGRESSIVE_GROWTH_FIXTURE_COUNT
        and summary["native_execution"]["status"] == "unavailable"
        and summary["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _CORRECTION in readiness["criteria"]["published_resistance_results"]["evidence"]
    )


def test_local_vm_handler_diversity_records_the_100_seed_collision_rate() -> None:
    report = _report(_HANDLERS)
    summary = _report(_SUMMARY)
    artifact = summary["artifacts"]["handler_diversity"]

    expect(
        artifact["sha256"] == hashlib.sha256(_HANDLERS.read_bytes()).hexdigest()
        and report["seed_count"] == _HANDLER_SEED_COUNT
        and report["schema_version"] == _HANDLER_REPORT_SCHEMA_VERSION
        and report["opcode_assignment_unique_count"] == _HANDLER_SEED_COUNT
        and report["cross_seed_exact_normalised_matches"] == _HANDLER_COLLISION_COUNT
        and report["cross_seed_largest_normalised_cluster"] == _LARGEST_HANDLER_CLUSTER
        and report["within_seed_exact_normalised_matches"] == _WITHIN_SEED_HANDLER_COLLISION_COUNT
        and report["within_seed_has_exact_normalised_matches"] is False
        and artifact["handler_count"] == _HANDLER_SEED_COUNT * _HANDLER_COUNT_PER_SEED
        and artifact["match_rate"] == report["cross_seed_exact_normalised_match_rate"]
    )
