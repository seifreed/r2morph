"""Pin the local installed-wheel release validation to its source commit."""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "docs/release-validation-local-2026-11-16-2c50cff3.json"
_SOURCE_COMMIT = "2c50cff3d40c9a37831f4725c3222e8c7ed6a355"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXPECTED_SUITE_PASSED = 7006
_EXPECTED_SUITE_SKIPPED = 226


def _report() -> dict[str, object]:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def test_local_release_manifest_binds_source_and_alpha_version() -> None:
    report = _report()

    expect(report["source_commit"] == _SOURCE_COMMIT and report["package_version"] == "0.4.0-alpha.3")


def test_local_release_manifest_records_complete_installed_wheel_suite() -> None:
    suite = _report()["full_test_suite"]

    expect(
        suite["runner"] == "installed wheel from isolated virtual environment"
        and suite["collected_items"] == suite["passed"] + suite["skipped"]
        and suite["passed"] == _EXPECTED_SUITE_PASSED
        and suite["skipped"] == _EXPECTED_SUITE_SKIPPED
        and suite["failed"] == 0
    )


def test_local_release_manifest_pins_all_built_artifact_hashes() -> None:
    artifacts = _report()["artifacts"]

    expect(
        set(artifacts) == {"wheel", "sdist", "sbom"}
        and all(_SHA256.fullmatch(str(artifact["sha256"])) for artifact in artifacts.values())
        and all(artifact["size_bytes"] > 0 for artifact in artifacts.values())
    )


def test_local_release_manifest_keeps_unverified_release_steps_blocked() -> None:
    release_scope = _report()["release_scope"]

    expect(
        release_scope["provenance_attestation"] == "not_generated"
        and release_scope["pypi_publication"] == "not_performed"
        and release_scope["stable_release"] == "blocked"
    )
