"""Pin two current-source fuzz seeds across all three supported CI runners."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect
from tests.utils.source_evidence import source_script_sha256_at_commit

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/continuous-fuzz-2026-11-25-83f5bdf0-summary.json"
_SOURCE = "83f5bdf0eab7e6a6bba875125674a68ba9fd0489"
_SCRIPT_SHA256 = "19a7e41eaea0d6e4f891c52723597dc75e7626da9b0ec4b2cebd5096ca13a9bf"
_CASES_PER_TARGET = 5_000
_MAX_PAYLOAD_BYTES = 4_096
_RUNS_PER_PLATFORM = 50_000
_TOTAL_TARGET_RUNS = 300_000
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
_RUNS = {
    45713863534: {"seed": 20260827, "diagnostics": 103},
    45713965616: {"seed": 20261125, "diagnostics": 104},
}
_REPORT_HASHES = {
    "20260827-macos-15": "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    "20260827-ubuntu-latest": "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    "20260827-windows-latest": "03cdcbe0b6a4fe2a373d605ba4bc1ed40d669674ba30614feb61988b7a1bd21c",
    "20261125-macos-15": "0e06f51e9bccbb917383b51aac0a1fb758092bc0cf2a279b55f98bb6c988ecfb",
    "20261125-ubuntu-latest": "0e06f51e9bccbb917383b51aac0a1fb758092bc0cf2a279b55f98bb6c988ecfb",
    "20261125-windows-latest": "f5a780a5418a936c5908eee68852babb6625011a9249d090b1a288576fa7969a",
}


def test_current_source_two_seed_campaigns_match_published_reports() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    configuration = summary["configuration"]
    execution = summary["execution"]

    expect(
        source_script_sha256_at_commit(_ROOT, _SOURCE, configuration["source_script"])
        == _SCRIPT_SHA256
        == configuration["source_script_sha256"]
    )
    expect(configuration["targets"] and set(configuration["targets"]) == _TARGETS)
    expect(configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET)
    expect(configuration["seeds"] == [20260827, 20261125])
    expect(execution["total_target_runs"] == _TOTAL_TARGET_RUNS and execution["total_failures"] == 0)

    runs = {run["run_id"]: run for run in execution["runs"]}
    expect(set(runs) == set(_RUNS))
    for run_id, expected in _RUNS.items():
        run = runs[run_id]
        expect(run["source_commit"] == _SOURCE and run["status"] == "success")
        expect(
            run["seed"] == expected["seed"] and set(run["platforms"]) == {"ubuntu-latest", "macos-15", "windows-latest"}
        )
        for platform, artifact in run["platforms"].items():
            key = f"{run['seed']}-{platform}"
            raw = (_ROOT / artifact["report"]).read_bytes()
            report = json.loads(raw)
            expect(hashlib.sha256(raw).hexdigest() == artifact["report_sha256"] == _REPORT_HASHES[key])
            expect(artifact["failure_count"] == 0 and artifact["target_runs"] == _RUNS_PER_PLATFORM)
            expect(artifact["parser_diagnostic_counts"] == {"macho_load_commands.warning": expected["diagnostics"]})
            expect(report["seed"] == run["seed"] and report["cases"] == _CASES_PER_TARGET)
            expect(
                report["max_payload"] == _MAX_PAYLOAD_BYTES
                and report["failures"] == []
                and report["failure_count"] == 0
            )
            expect(
                set(report["target_runs"]) == _TARGETS and set(report["target_runs"].values()) == {_CASES_PER_TARGET}
            )
