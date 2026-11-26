"""Pin the combined current-main evidence for repository shards 0 through 3."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-local-current-main-repository-shards-00-03-2026-11-26-summary.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_repository_shards_00_03_20261126.py"
_EXPECTED_TOOLS = {"angr", "binary-ninja", "custom", "ghidra", "ida-pro", "objdump", "radare2", "triton", "unicorn"}
_EXPECTED_FIXTURE_COUNT = 22
_EXPECTED_PASS_COUNT = 22
_EXPECTED_PASS_ROWS = 484
_EXPECTED_ANALYZER_ROWS = 4_356
_EXPECTED_COMPLETED_ROWS = 3_388
_EXPECTED_UNAVAILABLE_ROWS = 968
_SHARD_COUNT = 32
_EXPECTED_TREE_OIDS = {
    "r2morph": "54b5c7eb2cdcf56a684757f0147a539dec05ab87",
    "fixtures/dataset": "4599b46090109de0b42c58d034a8eb3f1f321512",
}


def test_four_repository_shards_have_complete_hash_bound_aggregate_evidence() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    scope = summary["scope"]
    reports: list[dict[str, Any]] = []
    for record in summary["shards"]:
        compressed = (_ROOT / record["raw_path"]).read_bytes()
        raw = json.loads(gzip.decompress(compressed))
        reports.append(raw)
        expect(
            hashlib.sha256(compressed).hexdigest() == record["raw_sha256"]
            and raw["fixture_shard"] == {"count": _SHARD_COUNT, "index": record["shard_index"]}
            and raw["summary"]["missing_pass_runs"] == raw["summary"]["missing_tool_runs"] == 0
            and raw["summary"]["error_tool_runs"] == 0
        )

    fixtures = [fixture for report in reports for sample in report["samples"] for fixture in [sample]]
    fixture_hashes = {
        sample["original"]: hashlib.sha256((_ROOT / "fixtures/dataset" / sample["original"]).read_bytes()).hexdigest()
        for sample in fixtures
    }
    completed_by_tool = {
        tool: sum(report["tool_summary"][tool]["completed"] for report in reports) for tool in _EXPECTED_TOOLS
    }
    unavailable_by_tool = {
        tool: sum(report["tool_summary"][tool]["unavailable"] for report in reports) for tool in _EXPECTED_TOOLS
    }
    expect(
        summary["production_source_tree_oids"] == _EXPECTED_TREE_OIDS
        and summary["benchmark_script_tree_oids"]
        == {
            "shards_00_01": "bd7fda8c7353e5dd43dcc1ef66e78fd55655f317",
            "shards_02_03": "f2dddc6284047ddb86f955b601d9a4c0dc4f4ffa",
        }
        and scope["fixture_shards"] == [0, 1, 2, 3]
        and scope["fixture_shard_count"] == _SHARD_COUNT
        and scope["fixture_count"] == len(fixtures) == _EXPECTED_FIXTURE_COUNT
        and len(fixture_hashes) == _EXPECTED_FIXTURE_COUNT
        and set(fixture_hashes) == {fixture["name"] for fixture in scope["fixtures"]}
        and fixture_hashes == {fixture["name"]: fixture["sha256"] for fixture in scope["fixtures"]}
        and all(len(report["pass_names"]) == _EXPECTED_PASS_COUNT for report in reports)
        and all(report["pass_names"] == reports[0]["pass_names"] for report in reports)
        and scope["expected_pass_runs"] == _EXPECTED_PASS_ROWS
        and scope["expected_tool_rows"] == _EXPECTED_ANALYZER_ROWS
        and scope["completed_tool_rows"] == _EXPECTED_COMPLETED_ROWS
        and scope["unavailable_tool_rows"] == _EXPECTED_UNAVAILABLE_ROWS
        and scope["errored_tool_rows"] == scope["missing_pass_runs"] == scope["missing_tool_runs"] == 0
        and scope["completed_tool_runs_by_tool"] == completed_by_tool
        and scope["unavailable_tool_runs_by_tool"] == unavailable_by_tool
        and completed_by_tool["ida-pro"] == completed_by_tool["ghidra"] == _EXPECTED_PASS_ROWS
        and unavailable_by_tool["triton"] == unavailable_by_tool["binary-ninja"] == _EXPECTED_PASS_ROWS
        and summary["release_gate"]["all_named_adversarial_analyzers"] == "open"
        and "binary-ninja" in summary["release_gate"]["optional_analyzers"]
        and "triton" in summary["release_gate"]["required_analyzers_unavailable"]
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and _SUMMARY.relative_to(_ROOT).as_posix()
        in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
        and _TEST_PATH in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    )
