"""Pin current-main VM handler diversity measurements and limitations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-vm-handler-diversity-local-2026-11-15-32seeds-summary.json"
_SOURCE_COMMIT = "7374619a98b4cd4fccfa5821027262b408049ffd"
_SEED_COUNT = 32
_HANDLERS_PER_SEED = 255
_CROSS_SEED_MATCHES = 4
_DUPLICATE_CLUSTER_SIZE = 2
_UNIQUE_CLUSTER_SIZE = 1
_ZERO = 0


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vm_handler_diversity_report_is_bound_to_current_main_source() -> None:
    summary = _json(_SUMMARY)
    report = summary["report"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and hashlib.sha256((_ROOT / "docs" / report["path"]).read_bytes()).hexdigest() == report["sha256"]
    )


def test_vm_handler_diversity_reports_cross_seed_collisions_and_no_within_seed_duplicates() -> None:
    summary = _json(_SUMMARY)
    measurement = summary["measurement"]

    expect(
        measurement["seed_count"] == _SEED_COUNT
        and measurement["handler_count_per_seed"] == _HANDLERS_PER_SEED
        and measurement["opcode_assignment_unique_count"] == _SEED_COUNT
        and measurement["cross_seed_exact_normalised_matches"] == _CROSS_SEED_MATCHES
        and measurement["cross_seed_largest_normalised_cluster"] == _DUPLICATE_CLUSTER_SIZE
        and measurement["within_seed_exact_normalised_matches"] == _ZERO
        and measurement["within_seed_largest_normalised_cluster"] == _UNIQUE_CLUSTER_SIZE
    )
