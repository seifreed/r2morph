"""Pin dependency-audit results for supported platform resolutions."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/dependency-audit-matrix-2026-11-17-51ab5ffb.json"
_SOURCE_COMMIT = "51ab5ffbda2daaa7cb36321fd385891f99f0a82d"
_REQUIREMENTS_SHA256 = "2cfcde79262fcc16d86a7c69e63fab0daedb1b46e9e92416ace8a077e69d415b"
_COMPONENT_COUNTS = {
    "linux_x86_64_manylinux_2_34_py312": 119,
    "linux_x86_64_manylinux_2_34_py313": 119,
    "macos_arm64_py313": 118,
    "windows_x86_64_py313": 86,
}
_HOST_PATH = re.compile(rb"/Users/|/home/|/private/tmp/|[A-Za-z]:\\Users\\")


def _report() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_REPORT_PATH.read_text(encoding="utf-8")))


def test_dependency_audit_matrix_reports_clean_platform_resolutions() -> None:
    report = _report()
    targets = report["targets"]

    expect(
        report["validated_source_commit"] == _SOURCE_COMMIT
        and report["requirements_sha256"] == _REQUIREMENTS_SHA256
        and report["overall_status"] == "passed"
        and report["known_vulnerabilities"] == 0
        and set(targets) == set(_COMPONENT_COUNTS)
        and all(
            target["status"] == "passed"
            and target["known_vulnerabilities"] == 0
            and target["resolved_components"] == _COMPONENT_COUNTS[name]
            for name, target in targets.items()
        )
    )


def test_dependency_audit_matrix_artifact_hashes_match_manifests_and_sboms() -> None:
    report = _report()
    targets = report["targets"]

    expect(
        all(
            hashlib.sha256(manifest_path.read_bytes()).hexdigest() == target["manifest"]["sha256"]
            and manifest_path.stat().st_size == target["manifest"]["size_bytes"]
            and hashlib.sha256(sbom_path.read_bytes()).hexdigest() == target["sbom"]["sha256"]
            and sbom_path.stat().st_size == target["sbom"]["size_bytes"]
            and len(json.loads(sbom_path.read_text(encoding="utf-8"))["components"])
            == target["sbom"]["component_count"]
            == _COMPONENT_COUNTS[name]
            for name, target in targets.items()
            for manifest_path, sbom_path in (
                (_ROOT / "docs" / target["manifest"]["path"], _ROOT / "docs" / target["sbom"]["path"]),
            )
        )
    )


def test_dependency_audit_matrix_documents_linux_wheel_resolution_limit() -> None:
    report = _report()
    linux_targets = (
        report["targets"]["linux_x86_64_manylinux_2_34_py312"],
        report["targets"]["linux_x86_64_manylinux_2_34_py313"],
    )

    expect(
        all(target["uv_python_platform"] == "x86_64-manylinux_2_34" for target in linux_targets)
        and any("does not declare a runtime glibc floor" in item for item in report["scope_limits"])
        and report["target_count"] == len(_COMPONENT_COUNTS)
    )


def test_dependency_audit_matrix_artifacts_contain_no_host_paths() -> None:
    report = _report()
    artifact_paths = [_ROOT / "docs" / artifact["manifest"]["path"] for artifact in report["targets"].values()] + [
        _ROOT / "docs" / artifact["sbom"]["path"] for artifact in report["targets"].values()
    ]

    expect(
        _HOST_PATH.search(_REPORT_PATH.read_bytes()) is None
        and all(_HOST_PATH.search(path.read_bytes()) is None for path in artifact_paths)
    )
