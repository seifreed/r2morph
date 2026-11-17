"""Pin bounded differential and VM evidence from the public workflow run."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/differential-run-2026-11-17-44081385675-summary.json"
_SOURCE_COMMIT = "b20a56c2b142701dd5e5bc329bd4a783204f8fb5"
_RUN_ID = 44081385675
_JOB_COUNT = 85
_PUBLIC_SAMPLE_COUNT = 360
_PUBLIC_PASS_COUNT = 6
_STATIC_RECOVERY_COUNT = 2160
_CORE_PASS_COUNT = 10
_CORE_RUN_COUNT = 10860
_CORE_APPLIED_RUN_COUNT = 3565
_EXTENDED_PASS_COUNT = 12
_EXTENDED_RUN_COUNT = 13032
_EXTENDED_APPLIED_RUN_COUNT = 3374
_MATURITY_DECOMPILER_BLOCKER_COUNT = 22
_VM_SHARD_COUNT = 48
_VM_CAPABILITY_COUNT = 9
_ONE_HUNDRED_PERCENT = 100.0
_ARTIFACT_SHA256 = {
    "differential-corpus": "dffc9c58ac5c691a04606b5d0204eb1d4cd80530c317daae859b7036efa32e6f",
    "extended-maturity": "e7719cab3fa076776b17cae3ee196c385629f4ad89ae44b46b0ea44e390df413",
    "maturity-evidence": "ce9234b9bb3bf3b5e717fddd82b0d6a0790eac5748158a078f1b6cc5ac9501d3",
    "public-compatibility": "14f2de716c78529c4a77f9ed3ad0791924658a5ea7c011996d04ddcd914f1759",
    "vm-semantic-contracts": "c675f96fe0c3c64ddb7c583fb96091ade9ac3270b8716b7e1ab1a494b0285014",
}
_HOST_PATH = re.compile(rb"/Users/|/home/|/private/tmp/|[A-Za-z]:\\Users\\")


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY_PATH.read_text(encoding="utf-8")))


def test_published_differential_workflow_binds_successful_run_and_platform_scope() -> None:
    report = _summary()
    workflow = report["workflow"]

    expect(
        workflow["run_id"] == _RUN_ID
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["status"] == "completed"
        and workflow["conclusion"] == "success"
        and workflow["jobs_completed"] == _JOB_COUNT
        and report["platform_scope"] == {"architecture": "x86-64", "format": "ELF", "os": "linux"}
    )


def test_published_differential_workflow_records_compatibility_and_decompiler_limits() -> None:
    compatibility = _summary()["public_compatibility"]

    expect(
        compatibility["built_samples"] == compatibility["passed_samples"] == _PUBLIC_SAMPLE_COUNT
        and compatibility["failed_samples"] == 0
        and len(compatibility["passes"]) == _PUBLIC_PASS_COUNT
        and all(
            result["samples"] == _PUBLIC_SAMPLE_COUNT and result["differential_failed"] == 0 and result["errors"] == 0
            for result in compatibility["pass_summary"].values()
        )
        and compatibility["static_recovery"]["analyzer"] == "radare2"
        and compatibility["static_recovery"]["measured_samples"] == _STATIC_RECOVERY_COUNT
        and compatibility["static_recovery"]["failed_samples"] == 0
        and all(
            compatibility["decompiler_effectiveness_status"][tool] == ["omitted"]
            for tool in ("binary_ninja", "ghidra", "ida_pro")
        )
    )


def test_published_differential_workflow_records_seed_and_maturity_outcomes() -> None:
    report = _summary()
    differential = report["differential_corpus"]
    maturity = report["extended_maturity"]
    vm = report["vm_semantic_contracts"]

    expect(
        differential["passes_covered"] == differential["passes_expected"] == _CORE_PASS_COUNT
        and differential["classified_runs"] == _CORE_RUN_COUNT
        and differential["applied_runs"] == _CORE_APPLIED_RUN_COUNT
        and differential["successful_seed_runs"] == _CORE_RUN_COUNT
        and differential["failed_seed_runs"] == differential["error_runs"] == 0
        and differential["semantic_success_percent"] == _ONE_HUNDRED_PERCENT
        and maturity["passes_covered"] == maturity["passes_expected"] == _EXTENDED_PASS_COUNT
        and maturity["classified_runs"] == _EXTENDED_RUN_COUNT
        and maturity["applied_runs"] == _EXTENDED_APPLIED_RUN_COUNT
        and maturity["successful_seed_runs"] == _EXTENDED_RUN_COUNT
        and maturity["failed_seed_runs"] == maturity["error_runs"] == 0
        and maturity["semantic_success_percent"] == _ONE_HUNDRED_PERCENT
        and maturity["maturity_blocker_totals"]["decompiler"] == _MATURITY_DECOMPILER_BLOCKER_COUNT
        and vm["shards"] == _VM_SHARD_COUNT
        and len(vm["capabilities"]) == _VM_CAPABILITY_COUNT
        and all(state == "regression-covered" for state in vm["capabilities"].values())
    )


def test_published_differential_workflow_compressed_artifacts_match_pinned_hashes() -> None:
    artifacts = _summary()["artifacts"]

    expect(
        set(artifacts) == set(_ARTIFACT_SHA256)
        and all(
            hashlib.sha256((_ROOT / artifact["path"]).read_bytes()).hexdigest() == _ARTIFACT_SHA256[name]
            and len(gzip.decompress((_ROOT / artifact["path"]).read_bytes())) == artifact["source_size_bytes"]
            for name, artifact in artifacts.items()
        )
    )


def test_published_differential_workflow_keeps_known_gates_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        readiness["status"] == "blocked"
        and all(
            readiness["criteria"][criterion]["status"] == "open"
            for criterion in (
                "all_named_adversarial_analyzers",
                "cross_platform_parity",
                "published_resistance_results",
            )
        )
        and readiness["blocking_criteria"]
        == ["all_named_adversarial_analyzers", "cross_platform_parity", "published_resistance_results"]
    )


def test_published_differential_workflow_artifacts_contain_no_host_paths() -> None:
    expect(
        _HOST_PATH.search(_SUMMARY_PATH.read_bytes()) is None
        and all(
            _HOST_PATH.search(gzip.decompress((_ROOT / artifact["path"]).read_bytes())) is None
            for artifact in _summary()["artifacts"].values()
        )
    )
