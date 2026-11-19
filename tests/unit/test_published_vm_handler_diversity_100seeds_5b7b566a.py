"""Pin the current-source handler-template diversity measurement and limits."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-vm-handler-diversity-local-2026-11-19-5b7b566a-100seeds-summary.json"
_SOURCE_COMMIT = "5b7b566a0a39e4012decf2010f7b9914ada84139"
_FIRST_SEED = 20261119
_SEED_COUNT = 100
_HANDLERS_PER_SEED = 255
_OPCODE_ASSIGNMENTS = 100
_CROSS_SEED_MATCHES = 38
_CROSS_SEED_CLUSTERS = 19
_WITHIN_SEED_MATCHES = 0
_ZERO = 0


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vm_handler_diversity_report_is_bound_to_source_and_raw_report() -> None:
    summary = _json(_SUMMARY)
    report = summary["report"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and hashlib.sha256((_ROOT / "docs" / report["path"]).read_bytes()).hexdigest() == report["sha256"]
    )


def test_vm_handler_diversity_reports_template_collisions_and_scope() -> None:
    summary = _json(_SUMMARY)
    measurement = summary["measurement"]
    report = _json(_ROOT / "docs" / summary["report"]["path"])

    expect(
        measurement["first_seed"] == _FIRST_SEED
        and measurement["seed_count"] == _SEED_COUNT
        and measurement["handler_count_per_seed"] == _HANDLERS_PER_SEED
        and measurement["opcode_assignment_unique_count"] == _OPCODE_ASSIGNMENTS
        and measurement["cross_seed_exact_normalised_matches"] == _CROSS_SEED_MATCHES
        and measurement["cross_seed_normalised_cluster_count"] == _CROSS_SEED_CLUSTERS
        and measurement["within_seed_exact_normalised_matches"] == _WITHIN_SEED_MATCHES
        and report["source_commit"] == _SOURCE_COMMIT
        and "templates only" in report["scope"]
        and "execute protected binaries" in summary["limitations"][0]
    )


def test_vm_resistance_readiness_remains_open() -> None:
    readiness = _json(_ROOT / "docs/one-zero-readiness.json")
    evidence = readiness["criteria"]["published_resistance_results"]

    expect(
        evidence["status"] == "open"
        and _SUMMARY.relative_to(_ROOT).as_posix() in evidence["evidence"]
        and "docs/protection-vm-handler-diversity-local-2026-11-19-5b7b566a-100seeds.json" in evidence["evidence"]
    )
