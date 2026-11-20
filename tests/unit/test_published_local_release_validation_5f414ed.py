"""Pin local package validation and its release limitations."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/release-validation-local-2026-11-20-5f414ed.json"
_SBOM = _ROOT / "docs/release-validation-local-2026-11-20-5f414ed-sbom.cdx.json"
_SOURCE_COMMIT = "5f414ed0584f991588642554d9bd1ad498ad91bd"
_WHEEL_SHA256 = "6b9a3a460d554a1cffb7560e0dc76f04c8f0fe12b5cba045c31c2b75d1c58688"
_SDIST_SHA256 = "076877f34ff6b5817164290a163b5c203ceb8c5eb36ab812891bf86b43c87c49"
_SBOM_SHA256 = "f5d7c9939f55722fae22a94b681c13a25e9db5a22b2aca7db02ddb4d4e88a202"
_SUITE_PASSED = 5_845
_SUITE_SKIPPED = 12
_WHEEL_SMOKE_TESTS = 318
_HOST_PATH = re.compile(rb"(?:/Users/|/home/|/private/tmp/|[A-Za-z]:\\Users\\)")


def _report_data() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_REPORT.read_text(encoding="utf-8")))


def test_local_release_manifest_pins_artifacts_and_dependency_audit() -> None:
    report = _report_data()
    artifacts = report["artifacts"]
    audit = report["dependency_audit"]

    expect(
        report["source_commit"] == _SOURCE_COMMIT
        and artifacts["wheel"]["sha256"] == _WHEEL_SHA256
        and artifacts["sdist"]["sha256"] == _SDIST_SHA256
        and artifacts["sbom"]["sha256"] == _SBOM_SHA256
        and hashlib.sha256(_SBOM.read_bytes()).hexdigest() == _SBOM_SHA256
        and audit["status"] == "passed"
        and audit["known_vulnerabilities"] == 0
        and audit["sbom_format"] == "CycloneDX JSON"
        and report["package_metadata"]["twine_check"] == "passed"
    )


def test_local_release_manifest_records_suite_and_open_release_gates() -> None:
    report = _report_data()
    suite = report["full_test_suite"]
    smoke = report["installed_wheel_smoke"]["selected_tests"]
    scope = report["release_scope"]

    expect(
        suite["passed"] == _SUITE_PASSED
        and suite["failed"] == 0
        and suite["skipped"] == _SUITE_SKIPPED
        and smoke["collected"] == smoke["passed"] == _WHEEL_SMOKE_TESTS
        and smoke["failed"] == 0
        and report["github_ci"]["conclusion"] == "pending"
        and scope["provenance_attestation"] == "not_generated"
        and scope["pypi_publication"] == "not_performed"
        and scope["stable_release"] == "blocked"
        and any("disabled coverage" in limit for limit in scope["limitations"])
    )


def test_local_sbom_contains_no_host_paths() -> None:
    expect(_HOST_PATH.search(_REPORT.read_bytes()) is None and _HOST_PATH.search(_SBOM.read_bytes()) is None)
