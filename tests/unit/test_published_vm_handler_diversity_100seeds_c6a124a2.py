"""Pin current-source handler-template diversity evidence and its limits."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-vm-handler-diversity-local-2026-11-20-c6a124a2-100seeds-summary.json"
_SOURCE_COMMIT = "c6a124a23d7a8a4fd459bc7238b91eaaf20b7097"
_FIRST_SEED = 20261119
_SEED_COUNT = 100
_HANDLERS_PER_SEED = 255
_CROSS_SEED_MATCHES = 32
_CROSS_SEED_CLUSTERS = 16
_ZERO = 0


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vm_handler_diversity_report_is_bound_to_source_and_raw_report() -> None:
    summary = _json(_SUMMARY)
    report = summary["report"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and report["sha256"] == hashlib.sha256((_ROOT / "docs" / report["path"]).read_bytes()).hexdigest()
        and _json(_ROOT / "docs" / report["path"])["source_commit"] == _SOURCE_COMMIT
    )


def test_vm_handler_diversity_records_remaining_template_collisions() -> None:
    summary = _json(_SUMMARY)
    measurement = summary["measurement"]
    report = _json(_ROOT / "docs" / summary["report"]["path"])

    expect(
        measurement["first_seed"] == _FIRST_SEED
        and measurement["seed_count"] == _SEED_COUNT
        and measurement["handler_count_per_seed"] == _HANDLERS_PER_SEED
        and measurement["cross_seed_exact_normalised_matches"] == _CROSS_SEED_MATCHES
        and measurement["cross_seed_normalised_cluster_count"] == _CROSS_SEED_CLUSTERS
        and measurement["within_seed_exact_normalised_matches"] == _ZERO
        and report["cross_seed_exact_normalised_matches"] == _CROSS_SEED_MATCHES
        and "templates only" in report["scope"]
        and "analyst attack cost" in summary["limitations"][0]
    )


def test_vm_resistance_readiness_remains_open() -> None:
    readiness = _json(_ROOT / "docs/one-zero-readiness.json")
    evidence = readiness["criteria"]["published_resistance_results"]

    expect(evidence["status"] == "open" and _SUMMARY.relative_to(_ROOT).as_posix() in evidence["evidence"])
