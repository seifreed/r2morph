"""Validate the versioned support and release contract."""

from __future__ import annotations

import importlib
import json
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
        "actions/attest-build-provenance@v2",
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


def main() -> int:
    try:
        package_version = _check_version()
        matrix = _load_matrix()
        _check_matrix(matrix, package_version)
        _check_changelog(package_version)
        _check_inventory()
        _check_ci_contract()
        _check_release_workflow()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"release contract failed: {exc}", file=sys.stderr)
        return 1
    print(f"release contract valid: {package_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
