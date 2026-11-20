"""Pin the 2026-11-20 cross-platform fuzz run to its workflow artifacts."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/continuous-fuzz-2026-11-20-44646998764-summary.json"
_SOURCE_COMMIT = "5f5078f7f8d33b961bde6c63365710eb87bcdb6f"
_SOURCE_SCRIPT_SHA256 = "6bf18f8c3d62906ab4cd571db492ef3cb3367481d2c752a487f2ed027c7c7bc8"
_WORKFLOW_RUN = 44_646_998_764
_SEED = 20260827
_CASES_PER_TARGET = 5000
_MAX_PAYLOAD_BYTES = 4096
_TARGET_RUNS_PER_PLATFORM = 50000
_TOTAL_TARGET_RUNS = 150000
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
_ARTIFACTS = {
    "ubuntu-latest": (14588728199, "sha256:c59bbfcee8409949ceb621c8ed53412b570a49149dfb94d5a1d3963d476ffeaa"),
    "macos-15": (14588942193, "sha256:54acc0c45a28869b306e23b7fb334cb5e0dc528dacaa6595b590710f2f0ab53a"),
    "windows-latest": (14589846935, "sha256:829d6af06b5e5001d65aa925edcd4aed8aa4feadfc76be524d9e2cc63bc614f4"),
}
_DIAGNOSTICS = {"macho_load_commands.warning": 103}


def _summary() -> dict[str, object]:
    return json.loads((_ROOT / _SUMMARY_PATH).read_text(encoding="utf-8"))


def test_manifest_binds_run_to_source_and_all_three_workflow_artifacts() -> None:
    summary = _summary()
    workflow = summary["workflow"]
    configuration = summary["configuration"]
    platforms = summary["execution"]["platforms"]

    expect(
        workflow["run_id"] == _WORKFLOW_RUN
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["status"] == "success"
        and set(platforms) == set(_ARTIFACTS)
        and hashlib.sha256((_ROOT / configuration["source_script"]).read_bytes()).hexdigest()
        == _SOURCE_SCRIPT_SHA256
        == configuration["source_script_sha256"]
    )


def test_archived_reports_match_hashes_and_cover_every_fuzz_target() -> None:
    summary = _summary()
    configuration = summary["configuration"]
    execution = summary["execution"]

    expect(
        configuration["seed"] == _SEED
        and configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET
        and configuration["max_payload_bytes"] == _MAX_PAYLOAD_BYTES
        and set(configuration["targets"]) == _TARGETS
        and execution["total_target_runs"] == _TOTAL_TARGET_RUNS
        and execution["total_failures"] == 0
    )
    for platform, (artifact_id, artifact_digest) in _ARTIFACTS.items():
        entry = execution["platforms"][platform]
        raw = gzip.decompress((_ROOT / entry["report"]).read_bytes())
        report = json.loads(raw)
        expect(
            entry["artifact_id"] == artifact_id
            and entry["artifact_archive_sha256"] == artifact_digest
            and hashlib.sha256(raw).hexdigest() == entry["report_sha256"]
            and entry["target_runs"] == _TARGET_RUNS_PER_PLATFORM
            and entry["failure_count"] == 0
            and entry["parser_diagnostic_counts"] == _DIAGNOSTICS
            and report["seed"] == _SEED
            and report["cases"] == _CASES_PER_TARGET
            and report["max_payload"] == _MAX_PAYLOAD_BYTES
            and report["failure_count"] == 0
            and report["target_runs"] == dict.fromkeys(_TARGETS, _CASES_PER_TARGET)
            and report["parser_diagnostic_counts"] == _DIAGNOSTICS
        )
