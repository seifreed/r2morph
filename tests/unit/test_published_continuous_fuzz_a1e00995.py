"""Pin two current-source fuzz seeds across all three CI platforms."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = _ROOT / "docs/continuous-fuzz-2026-11-25-a1e00995-summary.json"
_SOURCE = "a1e0099574190f2a9a426750b8286e5bc24ab40d"
_SCRIPT_HASH = "19a7e41eaea0d6e4f891c52723597dc75e7626da9b0ec4b2cebd5096ca13a9bf"
_CASES_PER_TARGET = 5000
_MAX_PAYLOAD_BYTES = 4096
_RUNS_PER_PLATFORM = 50000
_TOTAL_TARGET_RUNS = 300000
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
_PLATFORMS = {"ubuntu-latest", "macos-15", "windows-latest"}
_ARCHIVE_DIGESTS = {
    15071256889: "sha256:bdac92642d1c54909b2abf1833d66b1efe6d28fd8487f7b3b558fd268aae685d",
    15070514088: "sha256:5020ccbe05d1cba8b9c05a0f9c3259ad067eb38b0c1092beda4ac49848a69d94",
    15071795217: "sha256:86fd40e9503f807225225a033e864240a63b434067900ad1b14bfe73e26b8dec",
    15074336259: "sha256:d5351236b27fb7804e200f0c955797c5c8bbb3f283d9b1aa6e97b443195eae0f",
    15074247170: "sha256:a0dfa987bfaa116b1312fa22439322a4c906d9c97f0fc19be4ace96653797975",
    15073723434: "sha256:5d677707d25cfeddbdd6266edf49388928db77b4dade3cbd8ac42e7837489180",
}


def test_current_source_fuzz_reports_cover_two_seeds_and_three_platforms() -> None:
    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    configuration = manifest["configuration"]
    execution = manifest["execution"]
    runs = {run["run_id"]: run for run in execution["runs"]}

    expect(
        hashlib.sha256((_ROOT / configuration["source_script"]).read_bytes()).hexdigest() == _SCRIPT_HASH
        and configuration["source_script_sha256"] == _SCRIPT_HASH
        and set(configuration["targets"]) == _TARGETS
        and configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET
        and configuration["max_payload_bytes"] == _MAX_PAYLOAD_BYTES
        and configuration["seeds"] == [20260827, 20261125]
        and execution["total_target_runs"] == _TOTAL_TARGET_RUNS
        and execution["total_failures"] == 0
        and set(runs) == {45718344351, 45725093314}
    )

    archive_digests = {}
    for run_id, seed, expected_diagnostics in ((45718344351, 20260827, 103), (45725093314, 20261125, 104)):
        run = runs[run_id]
        expect(
            run["source_commit"] == _SOURCE
            and run["status"] == "success"
            and run["seed"] == seed
            and set(run["platforms"]) == _PLATFORMS
        )
        for _, artifact in run["platforms"].items():
            raw = (_ROOT / artifact["report"]).read_bytes()
            report = json.loads(raw)
            archive_digests[artifact["artifact_id"]] = artifact["artifact_archive_sha256"]
            expect(
                hashlib.sha256(raw).hexdigest() == artifact["report_sha256"]
                and artifact["failure_count"] == report["failure_count"] == 0
                and artifact["target_runs"] == _RUNS_PER_PLATFORM
                and report["seed"] == seed
                and report["cases"] == _CASES_PER_TARGET
                and report["max_payload"] == _MAX_PAYLOAD_BYTES
                and report["failures"] == []
                and set(report["target_runs"]) == _TARGETS
                and set(report["target_runs"].values()) == {_CASES_PER_TARGET}
                and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": expected_diagnostics}
            )

    expect(archive_digests == _ARCHIVE_DIGESTS)
