"""Validate the versioned support and release contract."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_matrix() -> dict[str, object]:
    path = ROOT / "docs" / "support-matrix.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _check_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_version = project["project"]["version"]
    init_text = (ROOT / "r2morph" / "__init__.py").read_text(encoding="utf-8")
    if f'__version__ = "{package_version}"' not in init_text:
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


def main() -> int:
    try:
        package_version = _check_version()
        _check_matrix(_load_matrix(), package_version)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"release contract failed: {exc}", file=sys.stderr)
        return 1
    print(f"release contract valid: {package_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
