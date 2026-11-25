"""Verify the current-source adversarial analyzer and VM diversity evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_RUN_ID = 45608329375
_SUMMARY = _ROOT / "docs/protection-adversarial-run-2026-11-25-45608329375-summary.json"
_REPORT = _ROOT / "docs/protection-adversarial-run-2026-11-25-45608329375.json.gz"
_MATURITY = _ROOT / "docs/protection-maturity-evidence-2026-11-25-45608329375.json.gz"
_SEEDS = _ROOT / "docs/protection-vm-seed-diversity-2026-11-25-45608329375.json"
_GRAMMAR = _ROOT / "docs/protection-bytecode-grammar-2026-11-25-45608329375.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_adversarial_run_45608329375.py"
_SOURCE_COMMIT = "36567b7c659df7bff5ef7b4b938f22d33765b990"
_FIXTURES, _GENERATED = 362, 200
_PASSES, _PASS_RUNS, _TOOL_ROWS = 22, 7964, 71676
_COMPLETED, _UNAVAILABLE = 55220, 16456
_UNICORN_COMPLETED, _UNICORN_UNAVAILABLE = 7436, 528
_DIVERSITY_SEEDS, _HANDLERS = 10, 2550
_SIMILARITY_COMPARISONS, _HIGH_SIMILARITY = 2295, 328
_STRIDE_VALUES, _PADDING_BYTES = 12, 2587


def _read_gzip(path: Path, expected_sha256: str) -> dict[str, object]:
    data = path.read_bytes()
    expect(hashlib.sha256(data).hexdigest() == expected_sha256)
    return json.loads(gzip.decompress(data))


def test_adversarial_campaign_binds_complete_classification_and_tool_limits() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    report = _read_gzip(_REPORT, summary["artifacts"]["merged_report"]["sha256"])
    maturity = _read_gzip(_MATURITY, summary["maturity"]["sha256"])
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    campaign = report["summary"]
    tools = report["tool_summary"]

    expect(
        summary["run_id"] == _RUN_ID
        and summary["conclusion"] == "success"
        and summary["jobs"] == {"total": 33, "passed": 33, "failed": 0, "cancelled": 0}
        and summary["source_commit"] == _SOURCE_COMMIT
        and summary["corpus"]["sample_count"] == _FIXTURES
        and summary["corpus"]["generated_fixture_count"] == _GENERATED
        and summary["corpus"]["pass_count"] == len(report["pass_names"]) == _PASSES
        and campaign["expected_pass_runs"] == campaign["observed_pass_runs"] == _PASS_RUNS
        and campaign["expected_tool_runs"] == campaign["observed_tool_runs"] == _TOOL_ROWS
        and campaign["completed_tool_runs"] == _COMPLETED
        and campaign["unavailable_tool_runs"] == _UNAVAILABLE
        and campaign["error_tool_runs"] == campaign["missing_tool_runs"] == 0
        and all(
            tools[name]["completed"] == _PASS_RUNS and tools[name]["unavailable"] == tools[name]["errors"] == 0
            for name in ("angr", "custom", "ghidra", "objdump", "radare2", "triton")
        )
        and tools["unicorn"]["completed"] == _UNICORN_COMPLETED
        and tools["unicorn"]["unavailable"] == _UNICORN_UNAVAILABLE
        and tools["ida-pro"]["completed"] == tools["binary-ninja"]["completed"] == 0
        and tools["ida-pro"]["unavailable"] == tools["binary-ninja"]["unavailable"] == _PASS_RUNS
        and maturity["summary"]["blocker_totals"]["decompiler"] == 0
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and _SUMMARY.relative_to(_ROOT).as_posix()
        in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
        and _TEST_PATH in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    )


def test_vm_diversity_metrics_are_published_without_claiming_general_resistance() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    seeds = json.loads(_SEEDS.read_text(encoding="utf-8"))
    grammar = json.loads(_GRAMMAR.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    seed_sha256 = summary["artifacts"]["seed_diversity"]["sha256"]
    grammar_sha256 = summary["artifacts"]["bytecode_grammar"]["sha256"]

    expect(
        hashlib.sha256(_SEEDS.read_bytes()).hexdigest() == seed_sha256
        and hashlib.sha256(_GRAMMAR.read_bytes()).hexdigest() == grammar_sha256
        and seeds["seed_count"] == _DIVERSITY_SEEDS
        and seeds["cross_seed_exact_normalised_matches"] == 0
        and seeds["cross_seed_nearest_similarity_comparisons"] == _SIMILARITY_COMPARISONS
        and seeds["cross_seed_nearest_similarity_above_threshold"] == _HIGH_SIMILARITY
        and grammar["seed_count"] == _DIVERSITY_SEEDS
        and grammar["total_handlers"] == _HANDLERS
        and grammar["all_handler_stride_unique_count"] == _STRIDE_VALUES
        and grammar["total_padding_bytes"] == _PADDING_BYTES
        and summary["limits"]
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _SUMMARY.relative_to(_ROOT).as_posix() in readiness["criteria"]["published_resistance_results"]["evidence"]
        and _TEST_PATH in readiness["criteria"]["published_resistance_results"]["evidence"]
    )
