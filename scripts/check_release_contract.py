"""Validate the versioned support and release contract."""

from __future__ import annotations

import importlib
import json
import re
import sys
import tomllib
from pathlib import Path

try:
    from scripts.support_matrix import build_matrix
except ModuleNotFoundError:
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
)
_BANNED_BINARY_NINJA_OMISSION_PHRASES = (
    "Binary Ninja is explicitly omitted",
    "Binary Ninja is intentionally omitted",
    "Binary Ninja remains intentionally omitted",
    "Binary Ninja remains omitted by project decision",
    "Binary Ninja remains excluded by project decision",
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
    official_total = summary["official_evidenced_cells"] + summary["official_not_supported_cells"]
    non_official_total = summary["non_official_evidenced_cells"] + summary["non_official_not_supported_cells"]
    for fragment in (
        f"{summary['official_evidenced_cells']}/{official_total} evidenced cells for the official",
        f"{summary['non_official_evidenced_cells']}/{non_official_total} evidenced cells for non-official",
    ):
        if fragment not in readme:
            raise ValueError(f"README support summary is missing: {fragment}")


def _check_pass_maturity_gap_summary(matrix: dict[str, object]) -> None:
    summary = matrix["matrix"]["summary"]
    contract = " ".join((ROOT / "docs" / "pass-maturity.md").read_text(encoding="utf-8").split())
    fragments = (
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
    )
    for fragment in fragments:
        if fragment not in contract:
            raise ValueError(f"pass maturity summary is missing: {fragment}")


def _check_changelog(package_version: str) -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {package_version}" not in changelog:
        raise ValueError("changelog must contain the package version heading")


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
    checks = report.get("checks")
    if not isinstance(checks, list):
        raise ValueError("independent review artifact must contain checks")
    statuses = {check.get("name"): check.get("status") for check in checks if isinstance(check, dict)}
    if set(statuses) != INDEPENDENT_REVIEW_CHECKS:
        raise ValueError("independent review artifact checks are incomplete")
    if any(status != "passed" for status in statuses.values()):
        raise ValueError("independent review artifact contains a failed check")


def _check_independent_review_artifact() -> None:
    report = json.loads((ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    _validate_independent_review_artifact(report)


def _check_independent_review_packet_claims() -> None:
    packet = " ".join((ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8").split())
    for fragment in (
        "memory, direct/indirect calls, returns, flags, FP/SIMD, varargs/ABI, unwinding, TLS/signals, "
        "SSA, and liveness",
        "unsupported instructions fail closed",
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
    observed = {tool.get("tool") for tool in tools if isinstance(tool, dict)}
    if observed != ADVERSARIAL_TOOL_SLOTS:
        raise ValueError("adversarial benchmark artifact must contain every analyzer slot")


def _check_adversarial_benchmark_artifacts() -> None:
    for path in (
        ROOT / "docs" / "protection-adversarial-benchmark.json",
        ROOT / "docs" / "protection-adversarial-angr-local-2026-09-13-13214f9.json",
    ):
        _validate_adversarial_benchmark_artifact(json.loads(path.read_text(encoding="utf-8")))


def _check_documentation_links(documents: tuple[Path, ...] = _DOCUMENTATION_LINK_FILES) -> None:
    for document in documents:
        for target in _MARKDOWN_LINK_PATTERN.findall(document.read_text(encoding="utf-8")):
            target_path = target.split("#", 1)[0].strip().strip("<>")
            if not target_path or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if not (document.parent / target_path).exists():
                raise ValueError(f"missing documentation link: {target}")


def _check_documentation_claims() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "production" + "-ready" in readme:
        raise ValueError("README must not claim alpha support is production grade")
    corpus = (ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8")
    if any(phrase in corpus for phrase in _BANNED_BINARY_NINJA_OMISSION_PHRASES):
        raise ValueError("compatibility corpus must not claim Binary Ninja is intentionally omitted")
    if "Binary Ninja through its installed API" not in corpus:
        raise ValueError("compatibility corpus must retain the Binary Ninja availability-slot contract")


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
    for fragment in ("--passes all", "--require-tool-slots", "--require-applied"):
        if fragment not in adversarial:
            raise ValueError(f"adversarial benchmark workflow is missing: {fragment}")
    for fragment in ("--passes all", "--require-complete-evidence", "--require-applied", "differential-corpus-by-pass"):
        if fragment not in differential:
            raise ValueError(f"differential corpus workflow is missing: {fragment}")


def main() -> int:
    try:
        package_version = _check_version()
        matrix = _load_matrix()
        _check_matrix(matrix, package_version)
        _check_readme_support_summary(matrix)
        _check_pass_maturity_gap_summary(matrix)
        _check_changelog(package_version)
        _check_inventory()
        _check_vm_resistance_artifacts()
        _check_independent_review_artifact()
        _check_independent_review_packet_claims()
        _check_adversarial_benchmark_artifacts()
        _check_documentation_links()
        _check_documentation_claims()
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
