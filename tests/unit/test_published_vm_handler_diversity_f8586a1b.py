"""Pin the current-main VM handler diversity measurement and its scope."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-vm-handler-diversity-local-2026-11-15-f8586a1b-32seeds-summary.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_BLOCKERS = _ROOT / "docs/release-blockers.md"
_SOURCE_COMMIT = "f8586a1beb0068d53bcc9ebaf3009ce0e2e8e375"
_SEED_COUNT = 32
_HANDLERS_PER_SEED = 255
_NEAREST_COMPARISONS = 7905
_HIGH_SIMILARITY_COMPARISONS = 3439
_ZERO = 0
_REPORT_REFERENCE = "docs/protection-vm-handler-diversity-local-2026-11-15-f8586a1b-32seeds.json"
_SUMMARY_REFERENCE = "docs/protection-vm-handler-diversity-local-2026-11-15-f8586a1b-32seeds-summary.json"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_current_vm_handler_report_is_bound_to_pushed_source() -> None:
    summary = _json(_SUMMARY)
    report = summary["report"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and hashlib.sha256((_ROOT / "docs" / report["path"]).read_bytes()).hexdigest() == report["sha256"]
    )


def test_current_vm_handler_report_records_zero_exact_collisions() -> None:
    summary = _json(_SUMMARY)
    measurement = summary["measurement"]

    expect(
        measurement["seed_count"] == _SEED_COUNT
        and measurement["handler_count_per_seed"] == _HANDLERS_PER_SEED
        and measurement["opcode_assignment_unique_count"] == _SEED_COUNT
        and measurement["cross_seed_exact_normalised_matches"] == _ZERO
        and measurement["within_seed_exact_normalised_matches"] == _ZERO
        and measurement["cross_seed_nearest_similarity_comparisons"] == _NEAREST_COMPARISONS
        and measurement["cross_seed_nearest_similarity_above_threshold"] == _HIGH_SIMILARITY_COMPARISONS
    )


def test_current_vm_handler_report_preserves_scope_limitations() -> None:
    summary = _json(_SUMMARY)

    expect(
        "Independent human adversarial validation remains pending." in summary["limitations"]
        and "one generated interpreter" in summary["limitations"][0]
    )


def test_current_vm_handler_evidence_is_registered_without_closing_release_gate() -> None:
    readiness = _json(_READINESS)
    criterion = readiness["criteria"]["published_resistance_results"]

    expect(
        criterion["status"] == "open"
        and _REPORT_REFERENCE in criterion["evidence"]
        and _SUMMARY_REFERENCE in criterion["evidence"]
    )


def test_current_vm_handler_blocker_documents_remaining_validation_scope() -> None:
    blockers = " ".join(_BLOCKERS.read_text(encoding="utf-8").split())

    expect(
        "zero exact" in blockers
        and "all 160 single-layer and nested tamper probes" in blockers
        and "independent human adversarial review" in blockers
    )
