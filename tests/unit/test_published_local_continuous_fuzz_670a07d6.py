"""Pin the current-main local continuous-fuzz campaign to its evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = "docs/continuous-fuzz-local-2026-11-19-670a07d6.json"
_REPORT_PATH = "docs/continuous-fuzz-local-2026-11-19-670a07d6-report.json"
_SOURCE_COMMIT = "670a07d6b6b88cdfeb470684ba4b17932f214af0"
_REPORT_SHA256 = "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53"
_CASES = 5_000
_MAX_PAYLOAD_BYTES = 4_096
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
    return cast(dict[str, object], json.loads((_ROOT / _MANIFEST_PATH).read_text(encoding="utf-8")))


def _report() -> dict[str, object]:
    return cast(dict[str, object], json.loads((_ROOT / _REPORT_PATH).read_text(encoding="utf-8")))


def test_published_local_fuzz_manifest_binds_source_commit_and_script_hash() -> None:
    manifest = _manifest()
    script_path = cast(str, manifest["source_script"])
    script_hash = hashlib.sha256((_ROOT / script_path).read_bytes()).hexdigest()

    expect(manifest["source_commit"] == _SOURCE_COMMIT and script_hash == manifest["source_script_sha256"])


def test_published_local_fuzz_manifest_matches_archived_report_hash() -> None:
    manifest = _manifest()
    report_hash = hashlib.sha256((_ROOT / _REPORT_PATH).read_bytes()).hexdigest()

    expect(report_hash == _REPORT_SHA256 == manifest["report_sha256"])


def test_published_local_fuzz_covers_all_ten_targets_five_thousand_times() -> None:
    manifest = _manifest()
    target_runs = cast(dict[str, int], manifest["target_runs"])

    expect(
        manifest["cases"] == _CASES
        and manifest["max_payload_bytes"] == _MAX_PAYLOAD_BYTES
        and set(target_runs) == set(_TARGETS)
        and all(target_runs[target] == _CASES for target in _TARGETS)
        and manifest["total_target_runs"] == _CASES * len(_TARGETS)
    )


def test_published_local_fuzz_records_zero_failures_and_parser_diagnostics() -> None:
    manifest = _manifest()
    report = _report()

    expect(
        manifest["failure_count"] == report["failure_count"] == 0
        and report["failures"] == []
        and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": 103}
    )


def test_published_local_fuzz_keeps_single_host_limitations_explicit() -> None:
    limitations = cast(list[str], _manifest()["limitations"])

    expect(
        "does not prove semantic equivalence for arbitrary transformed binaries" in limitations[0]
        and "does not establish cross-platform parity or adversarial resistance" in limitations[1]
    )
