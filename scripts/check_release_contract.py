"""Validate the versioned support and release contract."""

from __future__ import annotations

import importlib
import json
import re
import sys
import tomllib
from pathlib import Path

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
VM_RESISTANCE_SEED_COUNT = 10
VM_HANDLER_COUNT = 255
MINIMUM_VM_VARIANT_COUNT = 2
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
    maturity = matrix["maturity"]
    profiles = maturity["profiles"]
    required_fields = maturity["required_fields"]
    pass_profiles = maturity["pass_profiles"]
    pass_names = {entry["name"] for entry in matrix["passes"]}
    if set(pass_profiles) != pass_names:
        raise ValueError("maturity profile map must cover every pass exactly")
    for profile_name in set(pass_profiles.values()):
        profile = profiles[profile_name]
        if set(profile) != set(required_fields):
            raise ValueError(f"maturity profile has incomplete fields: {profile_name}")
    summary = matrix["matrix"]["summary"]
    if summary["official_evidence_percent"] != FULL_EVIDENCE_PERCENT:
        raise ValueError("official target must retain complete evidence")
    if summary["non_official_evidence_percent"] >= summary["official_evidence_percent"]:
        raise ValueError("non-official targets must not claim official-target parity")


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


def _check_documentation_links(documents: tuple[Path, ...] = _DOCUMENTATION_LINK_FILES) -> None:
    for document in documents:
        for target in _MARKDOWN_LINK_PATTERN.findall(document.read_text(encoding="utf-8")):
            target_path = target.split("#", 1)[0].strip().strip("<>")
            if not target_path or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if not (document.parent / target_path).exists():
                raise ValueError(f"missing documentation link: {target}")


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


def main() -> int:
    try:
        package_version = _check_version()
        matrix = _load_matrix()
        _check_matrix(matrix, package_version)
        _check_changelog(package_version)
        _check_inventory()
        _check_vm_resistance_artifacts()
        _check_independent_review_artifact()
        _check_documentation_links()
        _check_ci_contract()
        _check_release_workflow()
        _check_release_recovery_workflow()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"release contract failed: {exc}", file=sys.stderr)
        return 1
    print(f"release contract valid: {package_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
