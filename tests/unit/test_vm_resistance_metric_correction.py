"""Keep historical, unavailable VM tamper measurements out of resistance evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_LEDGER = _ROOT / "docs/vm-resistance-metric-correction-2026-11-20.json"
_AFFECTED_RECORD_COUNT = 90
_MISSING_PROBE_COUNT = 720


def _tamper_records(value: object) -> list[dict[str, object]]:
    if isinstance(value, dict):
        records = [value] if "all_tamper_probes_diverged" in value and "native_execution_available" in value else []
        for nested in value.values():
            records.extend(_tamper_records(nested))
        return records
    if isinstance(value, list):
        return [record for nested in value for record in _tamper_records(nested)]
    return []


def test_historical_unavailable_tamper_results_are_retracted_and_hash_bound() -> None:
    ledger = json.loads(_LEDGER.read_text(encoding="utf-8"))
    artifacts = cast(list[dict[str, object]], ledger["affected_artifacts"])
    affected_records = 0
    missing_probes = 0

    for artifact in artifacts:
        path = _ROOT / cast(str, artifact["path"])
        raw = path.read_bytes()
        report = json.loads(gzip.decompress(raw) if path.suffix == ".gz" else raw)
        records = _tamper_records(report)
        probes = [
            probe for record in records for probe in cast(list[dict[str, object]], record.get("tamper_probes", []))
        ]
        artifact_missing_probes = sum(probe.get("tampered_exit_code") is None for probe in probes)
        affected_records += len(records)
        missing_probes += artifact_missing_probes

        expect(
            hashlib.sha256(raw).hexdigest() == artifact["sha256"]
            and len(records) == artifact["affected_records"]
            and all(record["all_tamper_probes_diverged"] is True for record in records)
            and all(record["native_execution_available"] is False for record in records)
            and artifact["tamper_probes"] == len(probes)
            and artifact["missing_tampered_exit_codes"] == artifact_missing_probes == len(probes)
        )

    expect(
        ledger["status"] == "historical_tamper_divergence_claims_retracted"
        and affected_records == ledger["total_affected_records"] == _AFFECTED_RECORD_COUNT
        and missing_probes == ledger["total_missing_tampered_exit_codes"] == _MISSING_PROBE_COUNT
        and ledger["release_gate"] == "published_resistance_results remains open"
    )
