"""Pin current-source local package release checks and their open limits."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/release-validation-local-2026-11-17-b20a56c2.json"
_SBOM_PATH = _ROOT / "docs/release-validation-local-2026-11-17-b20a56c2-environment-sbom.cdx.json"
_SOURCE_COMMIT = "b20a56c2b142701dd5e5bc329bd4a783204f8fb5"
_WHEEL_SHA256 = "9017c521acd12ead97e01e40156772b5371504541764ddc376dbb2f291eede9d"
_SDIST_SHA256 = "6ed1f23c0a2d841f37988f96da7cd94240d0580d78cdf61a72ec262e2cf276e5"
_SBOM_SHA256 = "e597b960dd370254322e33139957f1136a4894d9b0075a29decbe06dc67a18d9"
_HOST_PATH = re.compile(r"(?:/Users/|/home/|/private/tmp/|[A-Za-z]:\\Users\\)")


def _report() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_REPORT_PATH.read_text(encoding="utf-8")))


def test_local_release_validation_pins_built_artifacts_and_environment_sbom() -> None:
    report = _report()
    artifacts = report["artifacts"]

    expect(
        report["source_commit"] == _SOURCE_COMMIT
        and artifacts["wheel"]["sha256"] == _WHEEL_SHA256
        and artifacts["sdist"]["sha256"] == _SDIST_SHA256
        and artifacts["local_environment_sbom"]["sha256"] == _SBOM_SHA256
        and hashlib.sha256(_SBOM_PATH.read_bytes()).hexdigest() == _SBOM_SHA256
        and report["package_metadata"]["twine_check"] == "passed"
    )


def test_local_release_validation_keeps_incomplete_audit_and_release_steps_open() -> None:
    report = _report()

    expect(
        report["dependency_audit"]["requirements_file"]["status"] == "incomplete"
        and report["dependency_audit"]["local_environment"]["known_vulnerabilities"] == 0
        and report["release_scope"]["provenance_attestation"] == "not_generated"
        and report["release_scope"]["pypi_publication"] == "not_performed"
        and report["release_scope"]["stable_release"] == "blocked"
    )


def test_local_release_validation_artifacts_contain_no_host_paths() -> None:
    contents = _REPORT_PATH.read_bytes() + _SBOM_PATH.read_bytes()

    expect(_HOST_PATH.search(contents.decode("utf-8")) is None)
