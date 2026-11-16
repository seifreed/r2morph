"""Pin the expanded local continuous-fuzz campaign to its source and output."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = "docs/continuous-fuzz-local-2026-11-16-1a5447dd.json"
_REPORT_PATH = "docs/continuous-fuzz-local-2026-11-16-1a5447dd-report.json"
_SOURCE_COMMIT = "1a5447ddcd67f255b3df2581db0d17e5bd5da61e"
_SOURCE_SHA256 = "73ebcacf4cd64857b07d948218872543172b471e53f701425241a5f7f2b01ad0"
_REPORT_SHA256 = "f22cbfbefdbf53e19a9de62178f45a01cd3daff0247775a6cb989b888026104b"
_CASES = 10_000
_MAX_PAYLOAD_BYTES = 32_768
_TARGETS = (
    "assembling",
    "binary_parsers",
    "binary_rewriter",
    "elf_header_parser",
    "macho_load_commands",
    "pe_header_parser",
    "relocations",
    "vm_bytecode",
    "vm_dispatcher",
    "vm_instruction_decoder",
)


def _manifest() -> dict[str, object]:
    return json.loads((_ROOT / _MANIFEST_PATH).read_text(encoding="utf-8"))


def _report() -> dict[str, object]:
    return json.loads((_ROOT / _REPORT_PATH).read_text(encoding="utf-8"))


def test_local_fuzz_manifest_binds_source_commit_and_script_hash() -> None:
    manifest = _manifest()
    source_hash = hashlib.sha256((_ROOT / manifest["source_script"]).read_bytes()).hexdigest()

    expect(manifest["source_commit"] == _SOURCE_COMMIT and source_hash == _SOURCE_SHA256)


def test_local_fuzz_manifest_matches_archived_report_hash() -> None:
    manifest = _manifest()
    report_hash = hashlib.sha256((_ROOT / manifest["report"]).read_bytes()).hexdigest()

    expect(report_hash == _REPORT_SHA256 == manifest["report_sha256"])


def test_local_fuzz_run_exercises_every_target_ten_thousand_times() -> None:
    manifest = _manifest()
    target_runs = manifest["target_runs"]

    expect(
        manifest["cases"] == _CASES
        and manifest["max_payload_bytes"] == _MAX_PAYLOAD_BYTES
        and set(target_runs) == set(_TARGETS)
        and all(target_runs[target] == _CASES for target in _TARGETS)
        and manifest["total_target_runs"] == _CASES * len(_TARGETS)
    )


def test_local_fuzz_report_records_zero_failures_and_expected_diagnostics() -> None:
    manifest = _manifest()
    report = _report()

    expect(
        manifest["failure_count"] == report["failure_count"] == 0
        and report["failures"] == []
        and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": 167}
    )


def test_local_fuzz_limits_remain_explicit() -> None:
    limitations = _manifest()["limitations"]

    expect(
        "did not prove semantic equivalence for arbitrary transformed binaries" in limitations[0]
        and "does not establish cross-platform parity or adversarial resistance" in limitations[1]
    )
