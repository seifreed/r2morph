"""Evidence-artifact validation for the release contract."""

from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Callable

try:
    from scripts.adversarial_benchmark import _tool_summary
    from scripts.independent_review import review as build_independent_review
except ModuleNotFoundError:
    from adversarial_benchmark import _tool_summary
    from independent_review import review as build_independent_review

try:
    from scripts.release_contract_common import (
        ADVERSARIAL_TOOL_SLOTS,
        INDEPENDENT_REVIEW_CHECKS,
        MAXIMUM_VM_HANDLER_SIMILARITY_ABOVE_THRESHOLD_PERCENT,
        MINIMUM_VM_VARIANT_COUNT,
        REQUIRED_VM_TARGET_OPERATION,
        REQUIRED_VM_TARGET_STRIDE_VALUES,
        ROOT,
        VM_ADVERSARIAL_VALIDATION,
        VM_HANDLER_COUNT,
        VM_RESISTANCE_SEED_COUNT,
    )
except ModuleNotFoundError:
    from release_contract_common import (
        ADVERSARIAL_TOOL_SLOTS,
        INDEPENDENT_REVIEW_CHECKS,
        MAXIMUM_VM_HANDLER_SIMILARITY_ABOVE_THRESHOLD_PERCENT,
        MINIMUM_VM_VARIANT_COUNT,
        REQUIRED_VM_TARGET_OPERATION,
        REQUIRED_VM_TARGET_STRIDE_VALUES,
        ROOT,
        VM_ADVERSARIAL_VALIDATION,
        VM_HANDLER_COUNT,
        VM_RESISTANCE_SEED_COUNT,
    )


def _validate_inventory(inventory: dict[str, object]) -> None:
    fixtures = inventory["fixtures"]
    if inventory["compatible_fixture_count"] != len(fixtures):
        raise ValueError("generated inventory count does not match fixture records")
    for fixture in fixtures:
        if fixture["all_semantic_equal"] is not True:
            raise ValueError("generated inventory contains a failed semantic comparison")
        if not fixture["runs"]:
            raise ValueError("generated inventory contains a fixture without runs")
        if fixture["baseline_runtime"]["status"] != "completed":
            raise ValueError("generated inventory baseline runtime did not complete")
        for run in fixture["runs"]:
            if run["runtime"]["status"] != "completed":
                raise ValueError("generated inventory run runtime did not complete")
            if run["runtime_observable_equal"] is not True:
                raise ValueError("generated inventory contains a failed runtime comparison")
    summary = inventory["summary"]
    expected_summary = {
        "failed_seed_runs": 0,
        "semantic_failures": 0,
        "semantic_passes": len(fixtures),
        "successful_seed_runs": sum(len(fixture["runs"]) for fixture in fixtures),
    }
    if summary != expected_summary:
        raise ValueError("generated inventory summary does not match fixture records")


def _check_inventory() -> None:
    inventory = json.loads((ROOT / "docs" / "protection-maturity-corpus.json").read_text(encoding="utf-8"))
    _validate_inventory(inventory)


def _validate_bytecode_diversification(bytecode: dict[str, object]) -> None:
    if (
        bytecode.get("seeds_with_target_handlers") != VM_RESISTANCE_SEED_COUNT
        or bytecode.get("seeds_without_target_handlers") != 0
    ):
        raise ValueError("bytecode grammar must find target handlers for every seed")
    if bytecode.get("target_stride_diverse") is not True:
        raise ValueError("bytecode grammar target handler stride must be diverse")
    if bytecode.get("target_stride_unique_count") != len(bytecode.get("target_stride_values", [])):
        raise ValueError("bytecode grammar target stride count must match stride values")
    if bytecode.get("target_stride_values") != REQUIRED_VM_TARGET_STRIDE_VALUES:
        raise ValueError("bytecode grammar target stride values changed")
    if bytecode.get("target_operation") != REQUIRED_VM_TARGET_OPERATION:
        raise ValueError("bytecode grammar target operation changed")
    if bytecode.get("target_stride_unique_count", 0) < MINIMUM_VM_VARIANT_COUNT:
        raise ValueError("bytecode grammar target handlers must record multiple strides")
    seeds = bytecode.get("seeds")
    if not isinstance(seeds, list) or any(
        not isinstance(seed, dict)
        or seed.get("handler_count") != VM_HANDLER_COUNT
        or not isinstance(seed.get("target_handler_count"), int)
        or seed["target_handler_count"] < 1
        or not seed.get("target_stride_values")
        for seed in seeds
    ):
        raise ValueError("bytecode grammar artifact must preserve per-seed target handler diversity")


def _validate_vm_resistance_artifacts(handler: dict[str, object], bytecode: dict[str, object]) -> None:
    if handler.get("seed_count") != VM_RESISTANCE_SEED_COUNT or bytecode.get("seed_count") != VM_RESISTANCE_SEED_COUNT:
        raise ValueError("VM resistance artifacts must cover ten seeds")
    if handler.get("adversarial_validation") != VM_ADVERSARIAL_VALIDATION:
        raise ValueError("handler clustering artifact must preserve pending adversarial validation scope")
    if bytecode.get("adversarial_validation") != VM_ADVERSARIAL_VALIDATION:
        raise ValueError("bytecode grammar artifact must preserve pending adversarial validation scope")
    if handler.get("cross_seed_has_exact_normalised_matches") is not False:
        raise ValueError("handler clustering must not contain exact cross-seed matches")
    if handler.get("cross_seed_largest_normalised_cluster") != 1:
        raise ValueError("handler clustering must keep normalized clusters unique")
    similarity_mean = handler.get("cross_seed_nearest_similarity_mean")
    similarity_threshold = handler.get("similarity_threshold")
    if not isinstance(similarity_mean, int | float) or not isinstance(similarity_threshold, int | float):
        raise ValueError("handler clustering must record similarity mean and threshold")
    if similarity_mean >= similarity_threshold:
        raise ValueError("handler clustering mean similarity must remain below the configured threshold")
    above_threshold_percent = handler.get("cross_seed_nearest_similarity_above_threshold_percent")
    if (
        not isinstance(above_threshold_percent, int | float)
        or above_threshold_percent > MAXIMUM_VM_HANDLER_SIMILARITY_ABOVE_THRESHOLD_PERCENT
    ):
        raise ValueError("handler clustering above-threshold similarity rate is too high")
    seeds = handler.get("seeds")
    if not isinstance(seeds, list) or any(
        not isinstance(seed, dict)
        or seed.get("handler_count") != VM_HANDLER_COUNT
        or seed.get("raw_unique_count") != seed.get("handler_count")
        or seed.get("normalised_unique_count") != seed.get("handler_count")
        for seed in seeds
    ):
        raise ValueError("handler clustering artifact must preserve per-seed handler uniqueness")
    if bytecode.get("all_handler_stride_unique_count") != len(bytecode.get("all_handler_stride_values", [])):
        raise ValueError("bytecode grammar stride count must match stride values")
    if bytecode.get("all_handler_stride_unique_count", 0) < MINIMUM_VM_VARIANT_COUNT:
        raise ValueError("bytecode grammar must record multiple handler strides")
    padding = bytecode.get("padding_histogram")
    if not isinstance(padding, dict) or len(padding) < MINIMUM_VM_VARIANT_COUNT:
        raise ValueError("bytecode grammar must record varied handler padding")
    _validate_bytecode_diversification(bytecode)


def _check_vm_resistance_artifacts() -> None:
    handler = json.loads((ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    _validate_vm_resistance_artifacts(handler, bytecode)


def _validate_independent_review_artifact(report: dict[str, object]) -> None:
    if report.get("passed") is not True:
        raise ValueError("independent review artifact must pass")
    if report.get("human_signoff") != "not-attested":
        raise ValueError("independent review artifact must not claim human signoff")
    release_decision = report.get("release_decision")
    if not isinstance(release_decision, dict) or release_decision.get("status") != "block-vm-milestone":
        raise ValueError("independent review artifact must block the VM milestone without human signoff")
    if release_decision.get("reason") != "automated evidence is not a substitute for external human review":
        raise ValueError("independent review artifact must require external human review")
    checks = report.get("checks")
    if not isinstance(checks, list):
        raise ValueError("independent review artifact must contain checks")
    statuses = {check.get("name"): check.get("status") for check in checks if isinstance(check, dict)}
    if set(statuses) != INDEPENDENT_REVIEW_CHECKS:
        raise ValueError("independent review artifact checks are incomplete")
    if any(status != "passed" for status in statuses.values()):
        raise ValueError("independent review artifact contains a failed check")


def _validate_independent_review_freshness(report: dict[str, object]) -> None:
    if report != build_independent_review(ROOT):
        raise ValueError("independent review artifact must match the current review output")


def _check_independent_review_artifact() -> None:
    report = json.loads((ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    _validate_independent_review_artifact(report)
    _validate_independent_review_freshness(report)


def _check_independent_review_packet_claims() -> None:
    packet = " ".join((ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8").split())
    for fragment in (
        "release_decision: block-vm-milestone",
        "memory, direct/indirect calls, returns, flags, FP/SIMD, varargs/ABI, unwinding, TLS/signals, "
        "SSA, and liveness",
        "unsupported instructions fail closed",
        "instruction address, mnemonic, type, size, bounded opcode preview, capability, and reason",
        "VM ISA/opcode diversification, dispatcher/handler alternatives, superinstructions, anti-tamper, "
        "and progressive bytecode protection",
        "fuzz properties and failure handling for dispatcher, relocations, and rewriting",
    ):
        if fragment not in packet:
            raise ValueError(f"independent review packet is missing: {fragment}")


def _validate_adversarial_benchmark_artifact(report: dict[str, object]) -> None:
    tools = report.get("tools")
    if not isinstance(tools, list):
        raise ValueError("adversarial benchmark artifact must contain tools")
    if report.get("tool_summary") != _tool_summary([{"tools": tools}]):
        raise ValueError("adversarial benchmark artifact tool summary must match tool rows")
    _validate_adversarial_signoff_blockers(report)
    observed = {tool.get("tool") for tool in tools if isinstance(tool, dict)}
    if observed != ADVERSARIAL_TOOL_SLOTS:
        raise ValueError("adversarial benchmark artifact must contain every analyzer slot")
    for tool in tools:
        if not isinstance(tool, dict):
            raise ValueError("adversarial benchmark artifact contains an invalid tool row")
        status = tool.get("status")
        if status == "completed":
            if not isinstance(tool.get("original"), dict) or not isinstance(tool.get("protected"), dict):
                raise ValueError("completed analyzer rows must include original and protected evidence")
        elif status == "unavailable":
            if not isinstance(tool.get("reason"), str) or not tool["reason"].strip():
                raise ValueError("unavailable analyzer rows must include a reason")
        else:
            raise ValueError("analyzer rows must be completed or unavailable")


def _validate_adversarial_signoff_blockers(report: dict[str, object]) -> None:
    signoff_blockers = report.get("release_signoff_blockers")
    if signoff_blockers != _adversarial_release_signoff_blockers(report):
        raise ValueError("adversarial benchmark artifact must expose release signoff blockers")
    if not isinstance(signoff_blockers, dict):
        raise ValueError("adversarial benchmark artifact release signoff blockers must be a map")
    if report.get("release_signoff_blocker_totals") != _blocker_totals(signoff_blockers):
        raise ValueError("adversarial benchmark artifact must expose release signoff blocker totals")


def _adversarial_release_signoff_blockers(report: dict[str, object]) -> dict[str, object]:
    tool_summary = report.get("tool_summary")
    if not isinstance(tool_summary, dict):
        return {}
    unavailable = {
        tool: summary["unavailable_reasons"]
        for tool, summary in tool_summary.items()
        if isinstance(tool, str)
        and isinstance(summary, dict)
        and summary.get("unavailable", 0) > 0
        and isinstance(summary.get("unavailable_reasons"), dict)
    }
    return {"unavailable_analyzers": unavailable} if unavailable else {}


def _blocker_totals(blockers: dict[str, object]) -> dict[str, int]:
    totals = {field: len(value) for field, value in blockers.items() if isinstance(value, (list, dict))}
    totals["blocker_categories"] = len(blockers)
    totals["total_release_signoff_blockers"] = sum(
        count for field, count in totals.items() if field != "blocker_categories"
    )
    return dict(sorted(totals.items()))


def _check_adversarial_benchmark_artifacts() -> None:
    for path in (
        ROOT / "docs" / "protection-adversarial-benchmark.json",
        ROOT / "docs" / "protection-adversarial-angr-local-2026-09-18-59898697.json",
    ):
        _validate_adversarial_benchmark_artifact(json.loads(path.read_text(encoding="utf-8")))


def _validate_angr_runtime_available(
    platform_name: str,
    find_module: Callable[[str], object | None],
    load_module: Callable[[str], object] = importlib.import_module,
) -> None:
    if platform_name == "win32":
        return
    if find_module("angr") is None:
        raise ValueError("angr must be importable for adversarial benchmark evidence")
    # Optional analyzer imports can fail at import time because of ABI or dependency mismatches.
    try:
        load_module("angr")
    except Exception as error:
        raise ValueError("angr must be importable for adversarial benchmark evidence") from error


def _check_angr_runtime_available() -> None:
    if sys.version_info[:2] >= (3, 14):
        return
    _validate_angr_runtime_available(sys.platform, importlib.util.find_spec)
