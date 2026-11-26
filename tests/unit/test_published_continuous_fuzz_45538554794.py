"""Pin current-source fuzz evidence to the successful three-platform run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect
from tests.utils.source_evidence import source_script_sha256_at_commit

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/continuous-fuzz-2026-11-25-45538554794-summary.json"
_SOURCE = "2ab350c7505bfab61842e512642a2aa72e1a2b84"
_RUN_ID = 45_538_554_794
_SCRIPT_HASH = "19a7e41eaea0d6e4f891c52723597dc75e7626da9b0ec4b2cebd5096ca13a9bf"
_CASES_PER_TARGET = 5_000
_SEED = 20_260_827
_MAX_PAYLOAD_BYTES = 4_096
_RUNS_PER_PLATFORM = 50_000
_TOTAL_RUNS = 150_000
_DIAGNOSTICS = {"macho_load_commands.warning": 103}
_TARGETS = {
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
}
_PLATFORMS = {
    "macos-15": (
        14988905477,
        "sha256:1b42d0ac73f7a616d6e062711037035523ee9c92804412d0e95b3c244e476cce",
        "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    ),
    "ubuntu-latest": (
        14988297034,
        "sha256:89be5ea65f05f2ce7502f97a8eeda4f2c0412bd148180f7c7838a87eba7c325b",
        "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    ),
    "windows-latest": (
        14987913947,
        "sha256:2174b92dc1a0d5251058039dddc07373902c340ad658fb5492bc889a907b6ef9",
        "03cdcbe0b6a4fe2a373d605ba4bc1ed40d669674ba30614feb61988b7a1bd21c",
    ),
}


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def test_manifest_binds_successful_current_source_run() -> None:
    summary = _summary()
    workflow = summary["workflow"]
    configuration = summary["configuration"]

    expect(
        workflow["source_commit"] == _SOURCE
        and workflow["run_id"] == _RUN_ID
        and workflow["status"] == "success"
        and workflow["url"] == "https://github.com/seifreed/r2morph/actions/runs/45538554794"
    )
    expect(
        source_script_sha256_at_commit(_ROOT, _SOURCE, configuration["source_script"])
        == _SCRIPT_HASH
        == configuration["source_script_sha256"]
    )
    expect(configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET)
    expect(configuration["seed"] == _SEED)
    expect(configuration["max_payload_bytes"] == _MAX_PAYLOAD_BYTES)
    expect(set(configuration["targets"]) == _TARGETS)


def test_platform_reports_match_artifacts_and_have_no_failures() -> None:
    summary = _summary()
    execution = summary["execution"]
    platforms = execution["platforms"]

    expect(set(platforms) == set(_PLATFORMS))
    expect(execution["total_target_runs"] == _TOTAL_RUNS)
    expect(execution["total_failures"] == 0)
    for platform, (artifact_id, archive_hash, report_hash) in _PLATFORMS.items():
        entry = platforms[platform]
        report_path = _ROOT / entry["report"]
        raw = report_path.read_bytes()
        report = json.loads(raw)

        expect(entry["artifact_id"] == artifact_id)
        expect(entry["artifact_archive_sha256"] == archive_hash)
        expect(hashlib.sha256(raw).hexdigest() == report_hash == entry["report_sha256"])
        expect(entry["target_runs"] == _RUNS_PER_PLATFORM and entry["failure_count"] == 0)
        expect(entry["parser_diagnostic_counts"] == _DIAGNOSTICS)
        expect(report["failures"] == [] and report["failure_count"] == 0)
        expect(report["seed"] == _SEED and report["cases"] == _CASES_PER_TARGET)
        expect(report["max_payload"] == _MAX_PAYLOAD_BYTES)
        expect(set(report["target_runs"]) == _TARGETS)
        expect(set(report["target_runs"].values()) == {_CASES_PER_TARGET})


def test_manifest_preserves_bounded_scope_and_open_gates() -> None:
    limits = " ".join(_summary()["limits"])

    expect(
        "does not prove semantic equivalence for arbitrary transformed binaries" in limits
        and "do not establish complete product parity or exhaustive fuzz coverage" in limits
        and "does not close the differential, compatibility, adversarial-resistance, or independent-review gates"
        in limits
    )
