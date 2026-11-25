"""Validate the completed source-bound analyzer and VM evidence campaign."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

from defusedxml import ElementTree as DefusedElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-run-2026-11-25-45548803519-summary.json"
_ANALYZER_PATH = _ROOT / "docs/protection-adversarial-run-2026-11-25-45548803519.json.gz"
_MATURITY_PATH = _ROOT / "docs/protection-maturity-adversarial-run-2026-11-25-45548803519.json.gz"
_RESISTANCE_PATH = _ROOT / "docs/protection-vm-resistance-run-2026-11-25-45548803519.json.gz"
_SEED_PATH = _ROOT / "docs/protection-vm-seed-diversity-run-2026-11-25-45548803519.json"
_GRAMMAR_PATH = _ROOT / "docs/protection-vm-bytecode-grammar-run-2026-11-25-45548803519.json"
_XML_PATH = _ROOT / "docs/protection-vm-resistance-run-2026-11-25-45548803519.xml"
_TEST_PATH = "tests/unit/test_published_adversarial_run_45548803519.py"
_RUN_ID = 45548803519
_SOURCE_COMMIT = "1dabf440aa7b2a9443a67c692fa14c03d24c9fe5"
_AGGREGATE_ARTIFACT_ID = 15006095271
_RESISTANCE_ARTIFACT_ID = 14995289075
_SEED_ARTIFACT_ID = 14995049836
_GRAMMAR_ARTIFACT_ID = 14995773249
_SHARD_COUNT = 32
_JOB_COUNT = 33
_SAMPLE_COUNT = 362
_GENERATED_FIXTURE_COUNT = 200
_PASS_COUNT = 22
_PASS_RUNS = 7964
_TOOL_COUNT = 9
_TOOL_RUNS = 71676
_COMPLETED_TOOL_RUNS = 55220
_UNAVAILABLE_TOOL_RUNS = 16456
_UNICORN_UNAVAILABLE_RUNS = 528
_VM_FIXTURE_COUNT = 15
_SEED_COUNT = 10
_GROWTH_FIXTURE_COUNT = 6
_SIMILARITY_COMPARISONS = 2295
_SIMILARITY_OVER_THRESHOLD = 328
_SIMILARITY_MAX = 0.9333333333333333
_COMPLETE_COVERAGE_PERCENT = 100.0
_VIRTUALIZED_FUNCTIONS = 639
_UNSUPPORTED_FUNCTIONS = 14
_COMPOSITION_CASE_COUNT = 46
_ZERO = 0
_CHUNK_BYTES = 1024 * 1024
_PATH_CONTEXT_BYTES = 256
_HOST_PATH = re.compile(rb"(?:/(?:Users|home|tmp|root|workspace|private/tmp)/|[A-Za-z]:\\Users\\)")
_TOOL_COUNTS = {
    "angr": (7964, 0),
    "binary-ninja": (0, 7964),
    "custom": (7964, 0),
    "ghidra": (7964, 0),
    "ida-pro": (0, 7964),
    "objdump": (7964, 0),
    "radare2": (7964, 0),
    "triton": (7964, 0),
    "unicorn": (7436, 528),
}


def _json(path: Path) -> dict[str, object]:
    with gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb") as report:
        return json.loads(report.read())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _uncompressed_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = _ZERO
    with gzip.open(path, "rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _contains_host_path(path: Path) -> bool:
    trailing_bytes = b""
    with gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            content = trailing_bytes + chunk
            if _HOST_PATH.search(content):
                return True
            trailing_bytes = content[-_PATH_CONTEXT_BYTES:]
    return False


def test_adversarial_archives_match_run_and_artifact_hashes() -> None:
    summary = _json(_SUMMARY_PATH)
    archives = summary["archives"]
    shard_artifacts = summary["shards"]["artifacts"]

    expect(
        summary["run_id"] == _RUN_ID
        and summary["source_commit"] == _SOURCE_COMMIT
        and summary["conclusion"] == "success"
        and summary["jobs"] == {"total": _JOB_COUNT, "passed": _JOB_COUNT, "failed": _ZERO, "skipped": _ZERO}
        and summary["shards"]["count"] == summary["shards"]["successful"] == _SHARD_COUNT
        and summary["shards"]["indices"] == list(range(_SHARD_COUNT))
        and len(shard_artifacts) == _SHARD_COUNT
        and {item["index"] for item in shard_artifacts} == set(range(_SHARD_COUNT))
        and all(re.fullmatch(r"[0-9a-f]{64}", item["zip_sha256"]) for item in shard_artifacts)
        and summary["artifacts"]["aggregate"]["id"] == _AGGREGATE_ARTIFACT_ID
        and summary["artifacts"]["vm_resistance"]["id"] == _RESISTANCE_ARTIFACT_ID
        and summary["artifacts"]["vm_seed_diversity"]["id"] == _SEED_ARTIFACT_ID
        and summary["artifacts"]["vm_bytecode_grammar"]["id"] == _GRAMMAR_ARTIFACT_ID
        and all(re.fullmatch(r"[0-9a-f]{64}", artifact["zip_sha256"]) for artifact in summary["artifacts"].values())
        and all(
            archive["sha256"] == _sha256(_ROOT / path)
            and archive["uncompressed_sha256"] == _uncompressed_digest(_ROOT / path)[0]
            and archive["uncompressed_size_bytes"] == _uncompressed_digest(_ROOT / path)[1]
            for path, archive in archives.items()
            if archive["format"] == "gzip-json"
        )
        and all(
            archive["sha256"] == _sha256(_ROOT / path) and archive["size_bytes"] == (_ROOT / path).stat().st_size
            for path, archive in archives.items()
            if archive["format"] != "gzip-json"
        )
        and all(not _contains_host_path(_ROOT / path) for path in archives)
    )


def test_all_analyzer_rows_are_accounted_for_with_gaps_explicit() -> None:
    summary = _json(_SUMMARY_PATH)
    report = _json(_ANALYZER_PATH)
    results = summary["results"]

    expect(
        summary["scope"]["platform"] == "Linux ELF x86-64"
        and summary["scope"]["sample_count"] == _SAMPLE_COUNT
        and summary["scope"]["generated_fixture_count"] == _GENERATED_FIXTURE_COUNT
        and summary["scope"]["pass_count"] == _PASS_COUNT
        and summary["scope"]["expected_pass_runs"] == _PASS_RUNS
        and summary["scope"]["expected_tool_count"] == _TOOL_COUNT
        and summary["scope"]["expected_tool_runs"] == _TOOL_RUNS
        and report["sample_count"] == _SAMPLE_COUNT
        and len(report["samples"]) == _SAMPLE_COUNT
        and len(report["pass_names"]) == _PASS_COUNT
        and results["observed_pass_runs"] == summary["scope"]["expected_pass_runs"] == _PASS_RUNS
        and results["pass_run_coverage_percent"] == _COMPLETE_COVERAGE_PERCENT
        and results["observed_tool_runs"] == summary["scope"]["expected_tool_runs"] == _TOOL_RUNS
        and results["completed_tool_runs"] == _COMPLETED_TOOL_RUNS
        and results["unavailable_tool_runs"] == _UNAVAILABLE_TOOL_RUNS
        and results["error_tool_runs"] == results["missing_tool_runs"] == _ZERO
        and results["tool_run_coverage_percent"] == _COMPLETE_COVERAGE_PERCENT
        and all(
            report["tool_summary"][name]["completed"] == completed
            and report["tool_summary"][name]["unavailable"] == unavailable
            and report["tool_summary"][name]["errors"] == _ZERO
            for name, (completed, unavailable) in _TOOL_COUNTS.items()
        )
        and report["tool_summary"]["binary-ninja"]["unavailable_reasons"]
        == {"module 'binaryninja' is unavailable": _PASS_RUNS}
        and report["tool_summary"]["ida-pro"]["unavailable_reasons"] == {"executable 'idat' is unavailable": _PASS_RUNS}
        and report["tool_summary"]["unicorn"]["unavailable"] == _UNICORN_UNAVAILABLE_RUNS
        and report["pass_summary"]["CodeVirtualization"]["applied"] == _SAMPLE_COUNT
        and report["pass_summary"]["CodeVirtualization"]["functions_virtualized"] == _VIRTUALIZED_FUNCTIONS
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == _UNSUPPORTED_FUNCTIONS
        and not _contains_host_path(_ANALYZER_PATH)
    )


def test_vm_resistance_report_preserves_scope_and_pending_review() -> None:
    summary = _json(_SUMMARY_PATH)
    resistance = _json(_RESISTANCE_PATH)
    seeds = _json(_SEED_PATH)
    grammar = _json(_GRAMMAR_PATH)
    maturity = _json(_MATURITY_PATH)
    xml = DefusedElementTree.parse(_XML_PATH).getroot()
    suite = next(xml.iter("testsuite"))
    readiness = _json(_ROOT / "docs/one-zero-readiness.json")
    evidence = readiness["criteria"]

    expect(
        summary["vm_resistance"]["fixture_count"] == resistance["fixture_count"] == _VM_FIXTURE_COUNT
        and summary["vm_resistance"]["seed_count"] == resistance["seed_count"] == _SEED_COUNT
        and resistance["semantic_parity"] is True
        and resistance["all_tamper_probes_diverged"] is True
        and resistance["progressive_growth_supported_fixture_count"] == _GROWTH_FIXTURE_COUNT
        and resistance["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and seeds["cross_seed_exact_normalised_matches"] == _ZERO
        and seeds["cross_seed_nearest_similarity_comparisons"] == _SIMILARITY_COMPARISONS
        and seeds["cross_seed_nearest_similarity_above_threshold"] == _SIMILARITY_OVER_THRESHOLD
        and seeds["cross_seed_nearest_similarity_max"] == _SIMILARITY_MAX
        and grammar["seed_count"] == _SEED_COUNT
        and maturity["summary"]["blocker_totals"]["composition"] == _ZERO
        and maturity["summary"]["composition"]["case_count"] == _COMPOSITION_CASE_COUNT
        and maturity["summary"]["composition"]["failure_count"]
        == maturity["summary"]["composition"]["error_count"]
        == maturity["summary"]["composition"]["skipped_count"]
        == _ZERO
        and suite.get("tests") == "10"
        and suite.get("failures") == suite.get("errors") == suite.get("skipped") == "0"
        and evidence["all_named_adversarial_analyzers"]["status"] == "open"
        and evidence["cross_platform_parity"]["status"] == "open"
        and evidence["published_resistance_results"]["status"] == "open"
        and all(
            path in evidence[key]["evidence"]
            for key, path in (
                (
                    "all_named_adversarial_analyzers",
                    "docs/protection-adversarial-run-2026-11-25-45548803519-summary.json",
                ),
                ("all_named_adversarial_analyzers", "tests/unit/test_published_adversarial_run_45548803519.py"),
                ("published_resistance_results", "docs/protection-vm-resistance-run-2026-11-25-45548803519.json.gz"),
                ("published_resistance_results", "tests/unit/test_published_adversarial_run_45548803519.py"),
            )
        )
    )
