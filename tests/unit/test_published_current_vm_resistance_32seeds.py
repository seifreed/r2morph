"""Verify current-source, multi-fixture VM resistance evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-vm-resistance-local-2026-11-15-32seed-10fixtures-summary.json"
_ARCHIVE = _ROOT / "docs/protection-vm-resistance-local-2026-11-15-32seed-10fixtures.json.gz"
_SOURCE_COMMIT = "7374619a98b4cd4fccfa5821027262b408049ffd"
_FIXTURE_COUNT = 10
_SEED_COUNT = 32
_GROWTH_FIXTURE_COUNT = 7
_ZERO = 0
_CORRECTION = "docs/vm-resistance-metric-correction-2026-11-20.json"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_current_vm_resistance_archive_matches_published_hashes() -> None:
    summary = _json(_SUMMARY)
    artifact = summary["artifacts"]["campaign"]
    compressed = _ARCHIVE.read_bytes()
    raw = gzip.decompress(compressed)

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and artifact["sha256"] == hashlib.sha256(compressed).hexdigest()
        and artifact["size_bytes"] == len(compressed)
        and artifact["uncompressed_sha256"] == hashlib.sha256(raw).hexdigest()
        and artifact["uncompressed_size_bytes"] == len(raw)
    )


def test_current_vm_resistance_results_preserve_open_limitations() -> None:
    summary = _json(_SUMMARY)
    measurement = summary["measurement"]
    readiness = _json(_ROOT / "docs/one-zero-readiness.json")

    expect(
        summary["campaign"]["fixture_count"] == _FIXTURE_COUNT
        and summary["campaign"]["seed_count"] == _SEED_COUNT
        and measurement["semantic_parity"] is True
        and measurement["progressive_growth_supported_fixture_count"] == _GROWTH_FIXTURE_COUNT
        and measurement["handler_diversity_observed"] is False
        and summary["native_execution"]["status"] == "unavailable"
        and summary["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _CORRECTION in readiness["criteria"]["published_resistance_results"]["evidence"]
        and "docs/protection-vm-resistance-local-2026-11-15-32seed-10fixtures-summary.json"
        in readiness["criteria"]["published_resistance_results"]["evidence"]
        and summary["measurement"]["cross_fixture_distinct_artifacts"] is True
        and summary["handler_diversity"]["within_seed_exact_normalised_matches_per_fixture"] == _ZERO
    )
