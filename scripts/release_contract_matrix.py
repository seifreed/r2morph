"""Support-matrix and maturity-evidence checks for the release contract."""

from __future__ import annotations

import json

try:
    from scripts.support_matrix import build_matrix
except ModuleNotFoundError:
    from support_matrix import build_matrix

try:
    from scripts.release_contract_common import (
        ADVERSARIAL_TOOL_SLOTS,
        FULL_EVIDENCE_PERCENT,
        PUBLIC_CLI_ALIASES,
        ROOT,
        TIER_1_MATURITY_PROFILE,
        VM_RESISTANCE_EVIDENCE_QUALITY,
    )
except ModuleNotFoundError:
    from release_contract_common import (
        ADVERSARIAL_TOOL_SLOTS,
        FULL_EVIDENCE_PERCENT,
        PUBLIC_CLI_ALIASES,
        ROOT,
        TIER_1_MATURITY_PROFILE,
        VM_RESISTANCE_EVIDENCE_QUALITY,
    )


def _load_matrix() -> dict[str, object]:
    path = ROOT / "docs" / "support-matrix.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _check_tier_1_maturity(matrix: dict[str, object], pass_profiles: dict[str, str]) -> None:
    tier_1_passes = {entry["name"] for entry in matrix["passes"] if entry["stability"] == "tier-1"}
    tier_1_profiles = {name for name, profile_name in pass_profiles.items() if profile_name == TIER_1_MATURITY_PROFILE}
    if tier_1_profiles != tier_1_passes:
        raise ValueError("tier-1 passes must exactly match the tier-1 maturity profile")


def _check_maturity_profile_values(profile_name: str, profile: dict[str, object]) -> None:
    for field, value in profile.items():
        if isinstance(value, str):
            if not value.strip():
                raise ValueError(f"maturity profile has empty field: {profile_name}.{field}")
        elif isinstance(value, list):
            if not value or any(not isinstance(item, str) or not item.strip() for item in value):
                raise ValueError(f"maturity profile has empty field: {profile_name}.{field}")
        else:
            raise ValueError(f"maturity profile has invalid field type: {profile_name}.{field}")
    for field in ("unit_tests", "e2e_tests"):
        for evidence_path in profile[field]:
            if not (ROOT / evidence_path).exists():
                raise ValueError(f"maturity profile has missing evidence path: {profile_name}.{field}.{evidence_path}")


def _check_pass_selection_contract(matrix: dict[str, object], pass_names: set[str]) -> None:
    selection = matrix["selection"]
    cli_aliases = selection["cli_aliases"]
    engine_only = set(selection["engine_only_passes"])
    if set(cli_aliases.values()) | engine_only != pass_names:
        raise ValueError("pass selection must cover every pass exactly")
    if set(cli_aliases) != PUBLIC_CLI_ALIASES:
        raise ValueError("public CLI aliases changed without release contract update")
    if set(cli_aliases.values()) & engine_only:
        raise ValueError("public CLI aliases must not overlap engine-only passes")


def _check_vm_semantic_gap_evidence(matrix: dict[str, object]) -> None:
    vm_semantics = matrix["vm_semantics"]
    gap_scope = vm_semantics["gap_scope"]
    evidence = vm_semantics["gap_evidence"]
    if sorted(evidence) != sorted(gap_scope):
        raise ValueError("vm semantic gap evidence must cover every declared gap")
    summary = matrix["matrix"]["summary"]
    if summary["vm_semantic_gap_scope"] != gap_scope or summary["vm_semantic_gap_evidence"] != evidence:
        raise ValueError("vm semantic gap summary must match source evidence")
    totals = summary["vm_semantic_blocker_totals"]
    if totals["vm_semantic_gap_scope"] != len(gap_scope) or totals["total_vm_semantic_blockers"] != len(gap_scope):
        raise ValueError("vm semantic blocker totals must match declared gap scope")
    for gap, row in evidence.items():
        if not row["status"].endswith("-incomplete"):
            raise ValueError(f"vm semantic gap must remain incomplete until closed: {gap}")
        if not row["evidence"]:
            raise ValueError(f"vm semantic gap evidence is empty: {gap}")
        for evidence_path in row["evidence"]:
            if (
                isinstance(evidence_path, str)
                and not evidence_path.startswith("http")
                and not (ROOT / evidence_path).exists()
            ):
                raise ValueError(f"vm semantic gap evidence path is missing: {gap}.{evidence_path}")


def _check_vm_semantic_campaign_capabilities(
    matrix: dict[str, object],
    campaign: dict[str, object],
    report: dict[str, object],
) -> None:
    vm_semantics = matrix["vm_semantics"]
    capabilities = campaign.get("capabilities")
    report_capabilities = report.get("capability_summary")
    resolved = vm_semantics.get("resolved_evidence")
    summary = matrix["matrix"]["summary"]
    if not isinstance(resolved, dict) or summary.get("vm_semantic_resolved_evidence") != resolved:
        raise ValueError("vm semantic resolved evidence summary is stale")
    if not isinstance(capabilities, dict) or not isinstance(report_capabilities, dict):
        raise ValueError("vm semantic campaign capability summary is missing")
    if set(resolved) != set(capabilities):
        raise ValueError("vm semantic resolved evidence scope changed")
    if set(capabilities) != set(report_capabilities):
        raise ValueError("vm semantic campaign capability scope changed")
    for name, expected in capabilities.items():
        actual = report_capabilities.get(name)
        resolved_row = resolved.get(name)
        if not isinstance(expected, dict) or not isinstance(actual, dict):
            raise ValueError(f"vm semantic campaign capability is invalid: {name}")
        if not isinstance(resolved_row, dict) or resolved_row.get("status") != "campaign-measured":
            raise ValueError(f"vm semantic resolved evidence is incomplete: {name}")
        if expected.get("status") != "campaign-measured":
            raise ValueError(f"vm semantic campaign capability is not complete: {name}")
        for field in ("fixture_count", "passed_count", "failed_count"):
            if expected.get(field) != actual.get(field):
                raise ValueError(f"vm semantic campaign capability metadata is stale: {name}.{field}")


def _check_vm_semantic_campaign(matrix: dict[str, object]) -> None:
    vm_semantics = matrix["vm_semantics"]
    campaign = vm_semantics.get("campaign")
    if not isinstance(campaign, dict):
        raise ValueError("vm semantic campaign metadata is missing")
    artifact = campaign.get("artifact")
    if not isinstance(artifact, str) or not (ROOT / artifact).exists():
        raise ValueError("vm semantic campaign artifact is missing")
    report = json.loads((ROOT / artifact).read_text(encoding="utf-8"))
    if report.get("status") != "passed" or report.get("failed_count") != 0:
        raise ValueError("vm semantic campaign did not pass")
    for field in ("fixture_count", "passed_count", "seed_count"):
        if report.get(field) != campaign.get(field):
            raise ValueError(f"vm semantic campaign metadata is stale: {field}")
    _check_vm_semantic_campaign_capabilities(matrix, campaign, report)


def _check_vm_resistance_gap_evidence(matrix: dict[str, object]) -> None:
    summary = matrix["matrix"]["summary"]
    gap_scope = summary["vm_resistance_gap_scope"]
    evidence = summary["vm_resistance_gap_evidence"]
    if sorted(evidence) != sorted(gap_scope):
        raise ValueError("vm resistance gap evidence must cover every declared gap")
    if summary["vm_resistance_evidence_blockers"]["vm_resistance_gap_scope"] != gap_scope:
        raise ValueError("vm resistance evidence blockers must match declared gap scope")
    totals = summary["vm_resistance_blocker_totals"]
    if totals["vm_resistance_gap_scope"] != len(gap_scope) or totals["total_vm_resistance_blockers"] != len(gap_scope):
        raise ValueError("vm resistance blocker totals must match declared gap scope")
    for gap, row in evidence.items():
        expected_quality = VM_RESISTANCE_EVIDENCE_QUALITY.get(gap, "seed-diversity-only")
        if row["status"] == "complete" or row["evidence_quality"] != expected_quality:
            raise ValueError(f"vm resistance gap must remain pending adversarial review: {gap}")
        if not row["evidence"]:
            raise ValueError(f"vm resistance gap evidence is empty: {gap}")
        for evidence_path in row["evidence"]:
            if (
                isinstance(evidence_path, str)
                and not evidence_path.startswith("http")
                and not (ROOT / evidence_path).exists()
            ):
                raise ValueError(f"vm resistance gap evidence path is missing: {gap}.{evidence_path}")
    signoff = json.loads((ROOT / "docs" / "human-review-signoff.json").read_text(encoding="utf-8"))
    resolved = summary["vm_resistance_resolved_evidence"]
    if not isinstance(resolved, dict) or "human-adversarial-validation" not in resolved:
        raise ValueError("vm resistance resolved review evidence is missing")
    human_review = resolved["human-adversarial-validation"]
    if (
        human_review["status"] != "approved"
        or human_review["evidence_quality"] != "independent-human-review"
        or human_review["reviewed_commit"] != signoff["reviewed_commit"]
        or human_review["reviewer"] != signoff["reviewer"]
        or human_review["review_date_utc"] != signoff["review_date_utc"]
        or human_review["specialist_expertise_confirmation"] != signoff["specialist_expertise_confirmation"]
        or "docs/human-review-signoff.json" not in human_review["evidence"]
        or gap_scope
    ):
        raise ValueError("vm resistance independent review evidence is stale")


def _check_differential_gap_evidence(matrix: dict[str, object]) -> None:
    summary = matrix["matrix"]["summary"]
    scope = summary["differential_evidence_scope"]
    evidence = summary["differential_gap_evidence"]
    blockers = summary["differential_evidence_blockers"]
    if sorted(evidence) != sorted(scope):
        raise ValueError("differential gap evidence must cover every declared scope")
    if blockers["platform_gap_scope"] != scope["platform_gap_scope"]:
        raise ValueError("differential platform blockers must match declared gap scope")
    if blockers["corpus_gap_scope"] != scope["corpus_gap_scope"]:
        raise ValueError("differential corpus blockers must match declared gap scope")
    totals = summary["differential_blocker_totals"]
    platform_blockers = sum(len(values) for values in blockers["platform_gap_scope"].values())
    corpus_blockers = sum(len(values) for values in blockers["corpus_gap_scope"].values())
    if (
        totals["platform_gap_scope"] != platform_blockers
        or totals["corpus_gap_scope"] != corpus_blockers
        or totals["total_differential_blockers"] != platform_blockers + corpus_blockers
    ):
        raise ValueError("differential blocker totals must match declared gap scope")
    for gap, row in evidence.items():
        if row["status"] == "complete":
            raise ValueError(f"differential gap must remain incomplete until closed: {gap}")
        if not row["evidence"]:
            raise ValueError(f"differential gap evidence is empty: {gap}")
        for evidence_path in row["evidence"]:
            if (
                isinstance(evidence_path, str)
                and not evidence_path.startswith("http")
                and not (ROOT / evidence_path).exists()
            ):
                raise ValueError(f"differential gap evidence path is missing: {gap}.{evidence_path}")


def _check_adversarial_benchmark_evidence(matrix: dict[str, object]) -> None:
    summary = matrix["matrix"]["summary"]
    evidence = summary["adversarial_benchmark_evidence"]
    if set(evidence["expected_tools"]) != ADVERSARIAL_TOOL_SLOTS:
        raise ValueError("adversarial benchmark must declare every expected tool slot")
    measured = evidence["measured_available_tools"]
    unavailable = evidence["unavailable_reference_tools"]
    blockers = summary["adversarial_evidence_blockers"]
    if unavailable.get("binary-ninja", {}).get("status") != "unavailable":
        raise ValueError("Binary Ninja must remain an explicit unavailable analyzer slot")
    if blockers["binary_ninja_unavailable"] != ["binary-ninja"]:
        raise ValueError("Binary Ninja unavailable blocker must remain explicit")
    totals = summary["adversarial_blocker_totals"]
    incomplete_tool_count = len(blockers["incomplete_tool_coverage"])
    binary_ninja_count = len(blockers["binary_ninja_unavailable"])
    campaign_scope_count = len(blockers["comparable_campaign_scope"])
    if (
        totals["incomplete_tool_coverage"] != incomplete_tool_count
        or totals["binary_ninja_unavailable"] != binary_ninja_count
        or totals["comparable_campaign_scope"] != campaign_scope_count
        or totals["total_adversarial_blockers"] != incomplete_tool_count + binary_ninja_count + campaign_scope_count
    ):
        raise ValueError("adversarial blocker totals must match declared benchmark blockers")
    for tool, row in measured.items():
        if row["status"] != "completed":
            raise ValueError(f"adversarial benchmark measured tool is incomplete: {tool}")
    evidence_paths = list(evidence["campaign_evidence"])
    for section in (measured, unavailable):
        evidence_paths.extend(path for row in section.values() for path in row["evidence"])
    for evidence_path in evidence_paths:
        if (
            isinstance(evidence_path, str)
            and not evidence_path.startswith("http")
            and not (ROOT / evidence_path).exists()
        ):
            raise ValueError(f"adversarial benchmark evidence path is missing: {evidence_path}")


def _check_maturity_gap_evidence(matrix: dict[str, object]) -> None:
    summary = matrix["matrix"]["summary"]
    evidence = summary["maturity_gap_evidence"]
    blockers = summary["maturity_evidence_blockers"]
    expected_fields = set(summary["maturity_gap_passes"])
    if summary["native_evidence_gap_passes"]:
        expected_fields.add("native_evidence")
    if set(evidence) != expected_fields:
        raise ValueError("maturity gap evidence must cover every declared maturity gap")
    if blockers.get("native_evidence_gap_passes", []) != summary["native_evidence_gap_passes"]:
        raise ValueError("maturity native evidence blockers must match summary")
    if blockers.get("missing_fields_by_field", {}) != summary["maturity_gap_passes"]:
        raise ValueError("maturity field blockers must match summary")
    if blockers.get("missing_fields_by_pass", {}) != summary["maturity_gaps_by_pass"]:
        raise ValueError("maturity pass blockers must match summary")
    totals = summary["maturity_blocker_totals"]
    field_gap_total = sum(len(pass_names) for pass_names in summary["maturity_gap_passes"].values())
    if (
        totals["native_evidence_gap_passes"] != len(summary["native_evidence_gap_passes"])
        or totals["passes_with_maturity_field_gaps"] != len(summary["maturity_gaps_by_pass"])
        or totals["total_maturity_field_gaps"] != field_gap_total
        or totals["maturity_gap_categories"] != len(summary["maturity_gap_passes"])
        or totals["total_maturity_blockers"] != len(summary["native_evidence_gap_passes"]) + field_gap_total
    ):
        raise ValueError("maturity blocker totals must match declared gap scope")
    for gap, row in evidence.items():
        if not row["passes"]:
            raise ValueError(f"maturity gap evidence has no passes: {gap}")
        if not (row["status"].endswith("-incomplete") or row["status"].endswith("-unsupported")):
            raise ValueError(f"maturity gap must remain incomplete until closed: {gap}")
        for evidence_path in row["evidence"]:
            if (
                isinstance(evidence_path, str)
                and not evidence_path.startswith("http")
                and not (ROOT / evidence_path).exists()
            ):
                raise ValueError(f"maturity gap evidence path is missing: {gap}.{evidence_path}")


def _check_parity_gap_evidence(matrix: dict[str, object]) -> None:
    summary = matrix["matrix"]["summary"]
    evidence = summary["parity_gap_evidence"]
    blockers = summary["parity_evidence_blockers"]
    preview_targets = evidence["preview_evidence_targets"]
    zero_targets = evidence["zero_evidence_targets"]
    parity_targets = sorted(preview_targets + zero_targets, key=lambda row: (row["format"], row["architecture"]))
    if parity_targets != summary["non_official_gap_targets"]:
        raise ValueError("parity gap evidence must cover every non-official target")
    if blockers["parity_gap_scope"] != summary["parity_gap_scope"]:
        raise ValueError("parity gap scope blockers must match summary")
    if blockers["non_official_gap_targets"] != summary["non_official_gap_targets"]:
        raise ValueError("parity target blockers must match summary")
    totals = summary["parity_blocker_totals"]
    if totals["non_official_gap_targets"] != len(summary["non_official_gap_targets"]):
        raise ValueError("parity target blocker total must match summary")
    parity_gap_formats = len(summary["parity_gap_scope"]["formats"])
    parity_gap_architectures = len(summary["parity_gap_scope"]["architectures"])
    if (
        totals["parity_gap_formats"] != parity_gap_formats
        or totals["parity_gap_architectures"] != parity_gap_architectures
        or totals["total_parity_blockers"]
        != totals["non_official_gap_targets"] + parity_gap_formats + parity_gap_architectures
    ):
        raise ValueError("parity blocker totals must match declared gap scope")
    if any(
        row["evidence_percent"] >= summary["official_evidence_percent"] for row in blockers["non_official_gap_targets"]
    ):
        raise ValueError("non-official targets must remain below official parity")


def _check_vm_semantic_fixture_coverage(matrix: dict[str, object]) -> None:
    coverage = matrix["matrix"]["summary"]["vm_semantic_fixture_coverage"]
    if coverage != matrix["vm_semantics"]["fixture_coverage"]:
        raise ValueError("vm semantic fixture coverage summary must match source evidence")
    if not (ROOT / coverage["artifact"]).exists():
        raise ValueError("vm semantic fixture coverage artifact is missing")
    if coverage["fixture_count"] <= 0 or coverage["covered_capability_count"] != coverage["capability_count"]:
        raise ValueError("vm semantic fixture coverage must cover every declared capability")
    if coverage["unclassified_count"] != 0:
        raise ValueError("vm semantic fixture coverage must not contain unclassified fixtures")


def _check_matrix(matrix: dict[str, object], package_version: str) -> None:
    if matrix["release"] != package_version:
        raise ValueError("support matrix release must match package version")
    target = matrix["official_target"]
    if target != {"os": "linux", "format": "ELF", "architecture": "x86-64", "status": "supported"}:
        raise ValueError("official target must be Linux ELF x86-64")
    for pass_entry in matrix["passes"]:
        for evidence in pass_entry["evidence"]:
            if evidence.startswith("http"):
                continue
            if not (ROOT / evidence).exists():
                raise ValueError(f"missing evidence path: {evidence}")
    generated_matrix = build_matrix(matrix)
    if matrix["matrix"] != generated_matrix:
        raise ValueError("support matrix generated cells must be up to date")
    maturity = matrix["maturity"]
    profiles = maturity["profiles"]
    required_fields = maturity["required_fields"]
    pass_profiles = maturity["pass_profiles"]
    pass_names = {entry["name"] for entry in matrix["passes"]}
    _check_pass_selection_contract(matrix, pass_names)
    if set(pass_profiles) != pass_names:
        raise ValueError("maturity profile map must cover every pass exactly")
    for profile_name in set(pass_profiles.values()):
        profile = profiles[profile_name]
        if set(profile) != set(required_fields):
            raise ValueError(f"maturity profile has incomplete fields: {profile_name}")
        _check_maturity_profile_values(profile_name, profile)
    _check_tier_1_maturity(matrix, pass_profiles)
    summary = matrix["matrix"]["summary"]
    if summary["official_evidence_percent"] != FULL_EVIDENCE_PERCENT:
        raise ValueError("official target must retain complete evidence")
    if summary["non_official_evidence_percent"] >= summary["official_evidence_percent"]:
        raise ValueError("non-official targets must not claim official-target parity")
    _check_adversarial_benchmark_evidence(matrix)
    _check_differential_gap_evidence(matrix)
    _check_maturity_gap_evidence(matrix)
    _check_parity_gap_evidence(matrix)
    _check_vm_semantic_fixture_coverage(matrix)
    _check_vm_semantic_campaign(matrix)
    _check_vm_semantic_gap_evidence(matrix)
    _check_vm_resistance_gap_evidence(matrix)
