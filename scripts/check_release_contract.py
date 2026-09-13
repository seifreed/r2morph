"""Validate the versioned support and release contract."""

from __future__ import annotations

import importlib
import json
import re
import sys
import tomllib
from pathlib import Path

try:
    from scripts.adversarial_benchmark import _tool_summary
    from scripts.independent_review import review as build_independent_review
    from scripts.protection_maturity_baseline import CORPUS_PASS_NAMES
    from scripts.support_matrix import build_matrix
except ModuleNotFoundError:
    from adversarial_benchmark import _tool_summary
    from independent_review import review as build_independent_review
    from protection_maturity_baseline import CORPUS_PASS_NAMES
    from support_matrix import build_matrix

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_CI_JOBS = (
    "lint",
    "typecheck",
    "property-validation",
    "stable-tests",
    "unit-tests",
    "integration-tests",
    "product-smoke-tests",
    "cross-platform-tests",
    "package-smoke",
)
MINIMUM_COVERAGE_PERCENT = 75
FULL_EVIDENCE_PERCENT = 100.0
TIER_1_MATURITY_PROFILE = "tier-1-native"
PUBLIC_CLI_ALIASES = {"block", "expand", "nop", "register", "substitute"}
VM_RESISTANCE_SEED_COUNT = 10
VM_HANDLER_COUNT = 255
MINIMUM_VM_VARIANT_COUNT = 2
ADVERSARIAL_TOOL_SLOTS = {
    "angr",
    "binary-ninja",
    "custom",
    "ghidra",
    "ida-pro",
    "objdump",
    "radare2",
    "triton",
    "unicorn",
}
INDEPENDENT_REVIEW_CHECKS = {
    "adversarial_benchmark_evidence",
    "adversarial_corpus_evidence",
    "binary_ninja_benchmark_contract",
    "fppackedidxnb_regression_evidence",
    "ghidra_corpus_evidence",
    "ida_corpus_evidence",
    "ida_current_summary_evidence",
    "independent_fuzz_recheck",
    "parser_rewriter_fuzz_campaign",
    "support_matrix_consistency",
    "virtualization_fixture_coverage",
    "virtualization_fixture_headers",
}
_MARKDOWN_LINK_PATTERN = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
_DOCUMENTATION_LINK_FILES = (
    ROOT / "docs" / "independent-review-packet.md",
    ROOT / "docs" / "compatibility-corpus.md",
    ROOT / "docs" / "release-blockers.md",
)
_RELEASE_HONESTY_FILES = (
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    ROOT / "docs" / "independent-review-packet.md",
    ROOT / "docs" / "pass-maturity.md",
    ROOT / "docs" / "release-blockers.md",
)
_FORBIDDEN_RELEASE_CLAIMS = (
    "production-ready",
    "production ready",
    "ready to ship",
    "full parity",
    "universal protector",
    "vm milestone complete",
    "vm milestone approved",
    "anti-tamper approved",
    "progressive bytecode protection approved",
    "external human review passed",
)
_BANNED_BINARY_NINJA_OMISSION_PHRASES = (
    "Binary Ninja is explicitly omitted",
    "Binary Ninja is intentionally omitted",
    "Binary Ninja remains intentionally omitted",
    "Binary Ninja remains omitted by project decision",
    "Binary Ninja remains excluded by project decision",
)
_RELEASE_BLOCKER_FRAGMENTS = (
    "Per-pass maturity remains incomplete",
    "Differential corpus coverage remains incomplete",
    "VM semantics remain incomplete for memory, calls, ABI, unwinding, TLS/signals, threads, FP/SIMD, and SSA/liveness",
    "PE, Mach-O, ARM, and AArch64 remain preview or experimental",
    "Binary Ninja is an explicit slot",
    "anti-tamper and progressive bytecode protection",
    "external human review records signoff",
)


def _load_matrix() -> dict[str, object]:
    path = ROOT / "docs" / "support-matrix.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _check_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_version = project["project"]["version"]
    init_path = ROOT / "r2morph" / "__init__.py"
    if init_path.exists():
        public_version_matches = f'__version__ = "{package_version}"' in init_path.read_text(encoding="utf-8")
    else:
        public_version_matches = importlib.import_module("r2morph").__version__ == package_version
    if not public_version_matches:
        raise ValueError("package and public version must match")
    return package_version


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


def _check_readme_support_summary(matrix: dict[str, object]) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    summary = matrix["matrix"]["summary"]
    stability_counts = summary["stability_counts"]
    official_total = summary["official_evidenced_cells"] + summary["official_not_supported_cells"]
    non_official_total = summary["non_official_evidenced_cells"] + summary["non_official_not_supported_cells"]
    for fragment in (
        f"{summary['official_evidenced_cells']}/{official_total} evidenced cells for the official",
        f"{summary['non_official_evidenced_cells']}/{non_official_total} evidenced cells for non-official",
        f"{summary['official_evidence_percent']}% evidence",
        f"{summary['non_official_evidence_percent']}% evidence",
        f"{stability_counts['tier-1']} passes as Tier 1",
        f"{stability_counts['experimental']} passes as experimental",
        f"{summary['performance_counts']['Not measured per pass.']} passes with no per-pass performance",
        (
            f"{summary['false_positive_risk_counts']['Not independently measured.']} with no independent "
            "false-positive measurement"
        ),
        (
            f"{summary['decompiler_effectiveness_counts']['Not independently measured.']} with no independent "
            "decompiler-effectiveness measurement"
        ),
        (
            f"{summary['compatibility_counts']['Composition with other passes is not contractually supported.']} "
            "without contractual composition support"
        ),
        (
            f"{summary['instructions_affected_counts']['Not exhaustively catalogued.']} without an exhaustive "
            "affected-instruction catalogue"
        ),
    ):
        if fragment not in readme:
            raise ValueError(f"README support summary is missing: {fragment}")


def _check_readme_pass_surface(matrix: dict[str, object]) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pass_surface = {
        "nop": ("NOP Insertion", "`-m nop`"),
        "substitute": ("Instruction Substitution", "`-m substitute`"),
        "register": ("Register Substitution", "`-m register`"),
        "instruction-expansion": ("Instruction Expansion", "`-m expand`"),
        "block-reordering": ("Block Reordering", "`-m block`"),
        "dead-code-injection": ("Dead Code Injection", "engine-only"),
        "control-flow-flattening": ("Control Flow Flattening", "engine-only"),
        "opaque-predicates": ("Opaque Predicates", "engine-only"),
        "code-virtualization": ("Code Virtualization", "engine-only"),
        "anti-disassembly": ("Anti-Disassembly", "engine-only"),
        "data-flow-mutation": ("Data Flow Mutation", "engine-only"),
        "short-jump-patching": ("Short Jump Patching", "engine-only"),
        "constant-unfolding": ("Constant Unfolding", "engine-only"),
        "code-mobility": ("Code Mobility", "engine-only"),
        "function-outlining": ("Function Outlining", "engine-only"),
        "api-hashing": ("API Hashing", "engine-only"),
        "import-obfuscation": ("Import Obfuscation", "engine-only"),
        "self-modifying-code": ("Self-Modifying Code", "engine-only"),
        "stack-strings": ("Stack Strings", "engine-only"),
        "string-obfuscation": ("String Obfuscation", "engine-only"),
        "pattern-substitution": ("Pattern Substitution", "engine-only"),
        "polymorphic-engine": ("Polymorphic Engine", "engine-only"),
    }
    for entry in matrix["passes"]:
        name = entry["name"]
        if name not in pass_surface:
            raise ValueError(f"README pass surface map is missing: {name}")
        display_name, surface = pass_surface[name]
        row_prefix = f"| **{display_name}** | {surface} |"
        if row_prefix not in readme:
            raise ValueError(f"README pass surface is missing: {row_prefix}")


def _check_readme_cross_platform_parity() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    for fragment in (
        "PE, Mach-O, ARM, and AArch64 evidence does not imply parity with Linux ELF x86-64",
        "equivalent CodeVirtualization support",
    ):
        if fragment not in readme:
            raise ValueError(f"README cross-platform parity warning is missing: {fragment}")


def _check_readme_differential_summary() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    workflow = (ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    corpus = " ".join((ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())
    for fragment in ("--passes all", "--require-applied", "--require-complete-evidence"):
        if fragment not in workflow or fragment not in readme:
            raise ValueError(f"README differential summary is missing workflow flag: {fragment}")
    for fragment in (
        "nine seed-derived command-line inputs",
        "exit code, stdout, stderr, created files, and declared observable effects",
        "runtime, size, transform-duration, runtime-duration, and static analyzer evidence",
    ):
        if fragment not in corpus:
            raise ValueError(f"compatibility corpus differential contract is missing: {fragment}")
    for fragment in (
        "nine seed-derived inputs",
        "exit code, stdout, stderr, created files, and declared observable effects",
        "runtime, output size, transform duration, runtime duration, and static analyzer evidence",
    ):
        if fragment not in readme:
            raise ValueError(f"README differential summary is missing: {fragment}")


def _check_pass_maturity_gap_summary(matrix: dict[str, object]) -> None:
    summary = matrix["matrix"]["summary"]
    contract = " ".join((ROOT / "docs" / "pass-maturity.md").read_text(encoding="utf-8").split())
    handler = json.loads((ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    stability_counts = summary["stability_counts"]
    maturity_profile_counts = summary["maturity_profile_counts"]
    fragments = (
        f"{summary['official_evidence_percent']}% official evidence",
        f"{summary['non_official_evidence_percent']}% non-official evidence",
        f"{stability_counts['tier-1']} tier-1 passes",
        f"{stability_counts['experimental']} experimental passes",
        f"{maturity_profile_counts['tier-1-native']} tier-1-native profile passes",
        f"{maturity_profile_counts['experimental-corpus-selected']} experimental-corpus-selected profile passes",
        f"{maturity_profile_counts['code-virtualization']} code-virtualization profile pass",
        f"{maturity_profile_counts['experimental']} experimental profile passes",
        f"{summary['performance_counts']['Not measured per pass.']} passes with no per-pass performance",
        (
            f"{summary['false_positive_risk_counts']['Not independently measured.']} with no independent "
            "false-positive measurement"
        ),
        (
            f"{summary['decompiler_effectiveness_counts']['Not independently measured.']} with no independent "
            "decompiler-effectiveness measurement"
        ),
        (
            f"{summary['compatibility_counts']['Composition with other passes is not contractually supported.']} "
            "without contractual composition support"
        ),
        (
            f"{summary['instructions_affected_counts']['Not exhaustively catalogued.']} without an exhaustive "
            "affected-instruction catalogue"
        ),
        f"{handler['seed_count']} seeds with {VM_HANDLER_COUNT} handlers per seed",
        f"{handler['cross_seed_exact_normalised_matches']} exact normalized cross-seed handler matches",
        f"{bytecode['all_handler_stride_unique_count']} handler stride values",
        "target handler stride diversity",
        "not human approval of anti-tamper or progressive bytecode protection",
    )
    for fragment in fragments:
        if fragment not in contract:
            raise ValueError(f"pass maturity summary is missing: {fragment}")


def _check_corpus_pass_selection_docs() -> None:
    maturity = " ".join((ROOT / "docs" / "pass-maturity.md").read_text(encoding="utf-8").split())
    compatibility = " ".join((ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())
    maturity_passes = ", ".join(f"`{pass_name}`" for pass_name in CORPUS_PASS_NAMES[:-1])
    compatibility_passes = ", ".join(CORPUS_PASS_NAMES[:-1])
    if f"{maturity_passes}, and `{CORPUS_PASS_NAMES[-1]}`." not in maturity:
        raise ValueError("pass maturity contract must name the public corpus selection")
    if f"for ten selected passes: {compatibility_passes}, and {CORPUS_PASS_NAMES[-1]}." not in compatibility:
        raise ValueError("compatibility corpus must name the full pass selection")


def _check_changelog(package_version: str) -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {package_version}" not in changelog:
        raise ValueError("changelog must contain the package version heading")
    if package_version == _check_version() and "VM milestone blocked until external human review" not in changelog:
        raise ValueError("changelog must preserve the VM milestone signoff blocker")


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
    if handler.get("cross_seed_has_exact_normalised_matches") is not False:
        raise ValueError("handler clustering must not contain exact cross-seed matches")
    if handler.get("cross_seed_largest_normalised_cluster") != 1:
        raise ValueError("handler clustering must keep normalized clusters unique")
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


def _check_adversarial_benchmark_artifacts() -> None:
    for path in (
        ROOT / "docs" / "protection-adversarial-benchmark.json",
        ROOT / "docs" / "protection-adversarial-angr-local-2026-09-13-13214f9.json",
    ):
        _validate_adversarial_benchmark_artifact(json.loads(path.read_text(encoding="utf-8")))


def _check_readme_adversarial_summary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    report_name = "protection-adversarial-angr-local-2026-09-13-13214f9.json"
    report = json.loads((ROOT / "docs" / report_name).read_text(encoding="utf-8"))
    tools = report["tools"]
    completed = sum(1 for tool in tools if tool["status"] == "completed")
    unavailable = sum(1 for tool in tools if tool["status"] == "unavailable")
    binary_ninja = next(tool for tool in tools if tool["tool"] == "binary-ninja")
    for fragment in (
        f"{completed} completed analyzer slots",
        f"{unavailable} unavailable analyzer slots",
        report_name,
        "Binary Ninja is an explicit analyzer slot",
        f"`binary-ninja` as {binary_ninja['status']}",
        binary_ninja["reason"],
    ):
        if fragment not in readme:
            raise ValueError(f"README adversarial summary is missing: {fragment}")


def _check_readme_vm_review_scope() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    packet = " ".join((ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8").split())
    review = json.loads((ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    release_decision = review["release_decision"]
    for fragment in (
        f"human_signoff: {review['human_signoff']}",
        f"release_decision: {release_decision['status']}",
        "memory, direct/indirect calls, returns, flags, FP/SIMD, varargs/ABI, unwinding, TLS/signals, "
        "SSA, and liveness paths remain explicit review scope",
        "unsupported instructions must fail closed",
        "partial protected functions",
        "instruction address, mnemonic, type, size, bounded opcode preview, capability, and reason",
        "VM ISA/opcode diversification, dispatcher/handler alternatives, superinstructions, anti-tamper, "
        "and progressive bytecode protection",
        "human-review scope before the virtualizer milestone can be marked complete",
    ):
        if fragment not in readme:
            raise ValueError(f"README VM review scope is missing: {fragment}")
    for fragment in (
        "VM ISA/opcode diversification, dispatcher/handler alternatives",
        "superinstructions, anti-tamper, and progressive bytecode protection",
    ):
        if fragment not in packet:
            raise ValueError(f"independent review packet VM scope is missing: {fragment}")


def _check_readme_vm_resistance_summary() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    handler = json.loads((ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    for fragment in (
        f"{handler['seed_count']} seeds with {VM_HANDLER_COUNT} handlers per seed",
        f"{handler['cross_seed_exact_normalised_matches']} exact normalized cross-seed handler matches",
        f"{bytecode['all_handler_stride_unique_count']} handler stride values",
        "target handler stride diversity",
        "protection-handler-clustering.json",
        "protection-bytecode-grammar.json",
    ):
        if fragment not in readme:
            raise ValueError(f"README VM resistance summary is missing: {fragment}")


def _check_documentation_links(documents: tuple[Path, ...] = _DOCUMENTATION_LINK_FILES) -> None:
    for document in documents:
        for target in _MARKDOWN_LINK_PATTERN.findall(document.read_text(encoding="utf-8")):
            target_path = target.split("#", 1)[0].strip().strip("<>")
            if not target_path or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if not (document.parent / target_path).exists():
                raise ValueError(f"missing documentation link: {target}")


def _forbidden_release_claims(text: str) -> tuple[str, ...]:
    normalized = text.lower()
    return tuple(phrase for phrase in _FORBIDDEN_RELEASE_CLAIMS if phrase in normalized)


def _check_documentation_claims() -> None:
    for document in _RELEASE_HONESTY_FILES:
        claims = _forbidden_release_claims(document.read_text(encoding="utf-8"))
        if claims:
            raise ValueError(f"{document.relative_to(ROOT)} contains unsupported release claim: {claims[0]}")
    corpus = (ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8")
    if any(phrase in corpus for phrase in _BANNED_BINARY_NINJA_OMISSION_PHRASES):
        raise ValueError("compatibility corpus must not claim Binary Ninja is intentionally omitted")
    if "Binary Ninja through its installed API" not in corpus:
        raise ValueError("compatibility corpus must retain the Binary Ninja availability-slot contract")


def _check_release_blockers() -> None:
    blockers = " ".join((ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8").split())
    for fragment in _RELEASE_BLOCKER_FRAGMENTS:
        if fragment not in blockers:
            raise ValueError(f"release blockers ledger is missing: {fragment}")


def _check_ci_contract() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for job in REQUIRED_CI_JOBS:
        if f"\n  {job}:" not in workflow:
            raise ValueError(f"CI is missing required job: {job}")
    for fragment in (
        "python -m build",
        "dist/*.whl",
        "import r2morph",
        "r2morph --version",
        "--no-cov --tb=short",
        "python -W error -m pytest",
        "windows-latest",
        "runner.os == 'Windows'",
        (
            "python -W error -m pytest -v tests/unit/test_circular_imports.py "
            "tests/unit/test_cli_basic_commands.py::test_cli_version_function --no-cov --tb=short"
        ),
        "python scripts/support_matrix.py --check docs/support-matrix.json",
    ):
        if fragment not in workflow:
            raise ValueError(f"CI is missing wheel smoke contract: {fragment}")

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pytest_options = project["tool"]["pytest"]["ini_options"]
    if pytest_options["filterwarnings"] != ["error"]:
        raise ValueError("pytest warnings must remain errors")
    if project["tool"]["coverage"]["report"]["fail_under"] < MINIMUM_COVERAGE_PERCENT:
        raise ValueError("coverage gate must be at least 75 percent")


def _check_release_workflow() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for fragment in (
        "sbom.cdx.json",
        "rm dist/sbom.cdx.json",
        "actions/attest-build-provenance@v4",
        "attestations: write",
        'gh run download "$GITHUB_RUN_ID" --name dist --dir dist',
        "dist/*.whl",
        "python -m pip install --force-reinstall dist/*.whl",
        "Run tests against installed wheel",
        "python -W error -m pytest --no-cov",
        'awk -v version="$RELEASE_VERSION"',
        "test -s /tmp/changes.md",
        "r2morph --version",
        "Require green CI for release commit",
        "--workflow ci.yml",
        '--commit "$GITHUB_SHA"',
        'test "$ci_conclusion" = "success"',
    ):
        if fragment not in workflow:
            raise ValueError(f"release workflow is missing: {fragment}")


def _check_release_recovery_workflow() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release-recovery.yml").read_text(encoding="utf-8")
    for fragment in (
        "workflow_dispatch:",
        "validate-release",
        "publish-pypi",
        'git rev-parse "${RELEASE_TAG}^{commit}"',
        'gh run download "$SOURCE_RUN_ID" --name dist --dir dist',
        "attestations: write",
        "actions/attest-build-provenance@v4",
        "softprops/action-gh-release@v2",
    ):
        if fragment not in workflow:
            raise ValueError(f"release recovery workflow is missing: {fragment}")


def _check_corpus_workflows() -> None:
    adversarial = (ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")
    differential = (ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    for fragment in (
        "--passes all",
        "--require-tool-slots",
        "--require-applied",
        "Validate adversarial campaign summary",
        "missing_pass_runs",
        "missing_tool_runs",
        "passes without applications",
    ):
        if fragment not in adversarial:
            raise ValueError(f"adversarial benchmark workflow is missing: {fragment}")
    for fragment in (
        "--passes all",
        "--require-complete-evidence",
        "--require-applied",
        "--count 3",
        "Validate differential campaign summary",
        "missing_corpus_passes",
        "total_complete_evidence_missing_runs",
        "passes_with_incomplete_coverage",
        "differential-corpus-by-pass",
    ):
        if fragment not in differential:
            raise ValueError(f"differential corpus workflow is missing: {fragment}")


def main() -> int:
    try:
        package_version = _check_version()
        matrix = _load_matrix()
        _check_matrix(matrix, package_version)
        _check_readme_support_summary(matrix)
        _check_readme_pass_surface(matrix)
        _check_readme_cross_platform_parity()
        _check_readme_differential_summary()
        _check_pass_maturity_gap_summary(matrix)
        _check_corpus_pass_selection_docs()
        _check_changelog(package_version)
        _check_inventory()
        _check_vm_resistance_artifacts()
        _check_independent_review_artifact()
        _check_independent_review_packet_claims()
        _check_adversarial_benchmark_artifacts()
        _check_readme_adversarial_summary()
        _check_readme_vm_review_scope()
        _check_readme_vm_resistance_summary()
        _check_documentation_links()
        _check_documentation_claims()
        _check_release_blockers()
        _check_ci_contract()
        _check_release_workflow()
        _check_release_recovery_workflow()
        _check_corpus_workflows()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"release contract failed: {exc}", file=sys.stderr)
        return 1
    print(f"release contract valid: {package_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
