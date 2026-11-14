"""Regression contracts for the pinned adversarial campaign evidence."""

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-adversarial-campaign-2026-11-11-4749bca3.json"
_EXPECTED_PASS_COUNT = 22
_EXPECTED_PASS_RUNS = 7964
_EXPECTED_ANALYZER_RUNS = 71676
_COMPLETED_ANALYZER_RUNS = 55220
_UNAVAILABLE_ANALYZER_RUNS = 16456
_EXPECTED_ADVERSARIAL_BLOCKERS = 17
_COMPLETE_COVERAGE_PERCENT = 100.0
_UNAVAILABLE_RUNS_BY_ANALYZER = {"binary-ninja": 7964, "ida-pro": 7964, "unicorn": 528}
_LATEST_RUN_ID = 43526206403
_LATEST_SAMPLE_COUNT = 362
_LATEST_PASS_RUNS = 7964
_LATEST_COMPLETED_ANALYZER_RUNS = 55220
_LATEST_EVIDENCE_BLOCKER_COUNT = 17
_LOCAL_VM_REPORT = _ROOT / "docs" / "protection-vm-resistance-local-2026-11-14-84e1202f.json"
_LOCAL_VM_RAW_REPORT = _ROOT / "docs" / "protection-vm-resistance-local-2026-11-14-84e1202f-macos.json"
_LOCAL_VM_COMMIT = "84e1202f09bb5265c3b8f8a4f5b21dd541901bfe"
_LOCAL_VM_FIXTURE_COUNT = 10
_LOCAL_VM_SEED_COUNT = 10
_LOCAL_VM_BUILD_COUNT = _LOCAL_VM_FIXTURE_COUNT * _LOCAL_VM_SEED_COUNT
_LOCAL_VM_PROGRESSIVE_GROWTH_FIXTURES = 7


def test_adversarial_campaign_covers_every_pass_without_missing_rows() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    campaign = report["campaign"]

    expect(
        campaign["status"] == "completed"
        and campaign["expected_pass_runs"] == campaign["observed_pass_runs"] == _EXPECTED_PASS_RUNS
        and campaign["missing_pass_runs"] == 0
        and campaign["error_pass_runs"] == 0
        and report["scope"]["pass_count"] == len(report["scope"]["pass_rows"]) == _EXPECTED_PASS_COUNT
        and campaign["required_decompiler_pass_count"] == _EXPECTED_PASS_COUNT
        and campaign["decompiler_incomplete_passes"] == []
    )


def test_adversarial_campaign_keeps_unavailable_analyzers_as_blockers() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    campaign = report["campaign"]

    expect(
        campaign["expected_analyzer_runs"] == campaign["observed_analyzer_runs"] == _EXPECTED_ANALYZER_RUNS
        and campaign["completed_analyzer_runs"] == _COMPLETED_ANALYZER_RUNS
        and campaign["unavailable_runs"] == _UNAVAILABLE_ANALYZER_RUNS
        and campaign["blocker_totals"]["total_adversarial_evidence_blockers"] == _EXPECTED_ADVERSARIAL_BLOCKERS
        and campaign["unavailable_runs_by_analyzer"] == _UNAVAILABLE_RUNS_BY_ANALYZER
        and campaign["completed_coverage_percent_by_analyzer"]["triton"] == _COMPLETE_COVERAGE_PERCENT
        and campaign["completed_runs_by_analyzer"]["triton"] == _EXPECTED_PASS_RUNS
    )


def test_vm_smoke_does_not_claim_general_adversarial_resistance() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    smoke = report["vm_resistance_smoke"]

    expect(
        smoke["evidence_quality"] == "automated-adversarial-smoke"
        and smoke["automated_status"] == "completed"
        and smoke["human_review_status"] == "pending-human-adversarial-review"
        and smoke["claim"] == "automated-smoke-only; general resistance is not established"
        and report["readiness"]["published_resistance_results"] == "open"
    )


def test_vm_smoke_report_hashes_match_pinned_reports() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    smoke = report["vm_resistance_smoke"]
    paths = {
        "adversarial": smoke["adversarial_report"],
        "seed_diversity": smoke["seed_diversity_report"],
        "bytecode_grammar": smoke["bytecode_grammar_report"],
    }
    hashes = {name: hashlib.sha256((_ROOT / path).read_bytes()).hexdigest() for name, path in paths.items()}

    expect(hashes == smoke["report_sha256"])


def test_completed_adversarial_run_archives_full_evidence_without_closing_open_gates() -> None:
    report_path = _ROOT / "docs" / "protection-adversarial-run-2026-11-14-43526206403.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    archive_path = _ROOT / report["archive"]["path"]
    archive = archive_path.read_bytes()
    merged_bytes = gzip.decompress(archive)
    merged = json.loads(merged_bytes)
    readiness = json.loads((_ROOT / "docs" / "one-zero-readiness.json").read_text(encoding="utf-8"))
    vm_reports = report["vm_resistance_smoke"]["reports"]
    vm_hashes = {
        name: hashlib.sha256((_ROOT / evidence["path"]).read_bytes()).hexdigest()
        for name, evidence in vm_reports.items()
    }

    expect(
        report["workflow"]["run_id"] == _LATEST_RUN_ID
        and report["workflow"]["conclusion"] == "success"
        and hashlib.sha256(archive).hexdigest() == report["archive"]["sha256"]
        and hashlib.sha256(merged_bytes).hexdigest() == report["archive"]["uncompressed_sha256"]
        and report["scope"]["sample_count"] == merged["sample_count"] == _LATEST_SAMPLE_COUNT
        and report["scope"]["expected_pass_runs"] == merged["summary"]["expected_pass_runs"] == _LATEST_PASS_RUNS
        and report["results"]["pass_errors"] == merged["summary"]["error_pass_runs"] == 0
        and report["results"]["completed_analyzer_runs"]
        == merged["summary"]["completed_tool_runs"]
        == _LATEST_COMPLETED_ANALYZER_RUNS
        and report["results"]["evidence_blocker_totals"]["total_adversarial_evidence_blockers"]
        == _LATEST_EVIDENCE_BLOCKER_COUNT
        and vm_hashes == {name: evidence["sha256"] for name, evidence in vm_reports.items()}
        and report["vm_resistance_smoke"]["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_current_local_vm_resistance_campaign_binds_wheel_and_raw_report() -> None:
    report = json.loads(_LOCAL_VM_REPORT.read_text(encoding="utf-8"))

    expect(
        report["commit"] == _LOCAL_VM_COMMIT
        and report["provenance"] == "local-installed-wheel"
        and hashlib.sha256(_LOCAL_VM_RAW_REPORT.read_bytes()).hexdigest() == report["campaign_report_sha256"]
        and report["runtime"]["wheel_sha256"] == "1fb60f55b089838eb370b1ffe9be1a1193a6013577f7b01c117f294490428f26"
    )


def test_current_local_vm_resistance_campaign_passes_automated_scope() -> None:
    summary = json.loads(_LOCAL_VM_REPORT.read_text(encoding="utf-8"))
    campaign = json.loads(_LOCAL_VM_RAW_REPORT.read_text(encoding="utf-8"))

    expect(
        summary["fixture_count"] == campaign["fixture_count"] == _LOCAL_VM_FIXTURE_COUNT
        and summary["seed_count"] == campaign["seed_count"] == _LOCAL_VM_SEED_COUNT
        and sum(len(fixture["seed_campaign"]["builds"]) for fixture in campaign["fixtures"]) == _LOCAL_VM_BUILD_COUNT
        and campaign["semantic_parity"]
        and campaign["cross_fixture_distinct_artifacts"]
        and campaign["all_tamper_probes_diverged"]
        and campaign["adversarial_recovery_probe_observed"]
        and campaign["progressive_growth_supported_fixture_count"] == _LOCAL_VM_PROGRESSIVE_GROWTH_FIXTURES
        and all(fixture["seed_campaign"]["no_partial_virtualization"] for fixture in campaign["fixtures"])
        and all(
            not fixture["anti_tamper"][layer]["native_execution_available"]
            for fixture in campaign["fixtures"]
            for layer in ("single_layer", "nested")
        )
    )


def test_current_local_vm_resistance_campaign_keeps_review_and_claim_open() -> None:
    summary = json.loads(_LOCAL_VM_REPORT.read_text(encoding="utf-8"))
    campaign = json.loads(_LOCAL_VM_RAW_REPORT.read_text(encoding="utf-8"))

    expect(
        summary["general_resistance_established"] is False
        and summary["human_adversarial_review"] == "pending-human-adversarial-review"
        and campaign["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and summary["native_elf_execution"] == "unavailable-on-macos"
    )


def test_current_local_vm_resistance_campaign_does_not_expose_host_paths() -> None:
    reports = _LOCAL_VM_REPORT.read_text(encoding="utf-8") + _LOCAL_VM_RAW_REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in reports for prefix in ("/Users/", "/Applications/", "/private/", "/home/")))
