"""Validate the versioned support and release contract."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.4.0-alpha.1"


def _load_matrix() -> dict[str, object]:
    path = ROOT / "docs" / "support-matrix.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _check_version() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_version = project["project"]["version"]
    init_text = (ROOT / "r2morph" / "__init__.py").read_text(encoding="utf-8")
    if package_version != EXPECTED_VERSION or f'__version__ = "{EXPECTED_VERSION}"' not in init_text:
        raise ValueError("package and public version must be 0.4.0-alpha.1")


def _check_matrix(matrix: dict[str, object]) -> None:
    target = matrix["official_target"]
    if target != {"os": "linux", "format": "ELF", "architecture": "x86-64", "status": "supported"}:
        raise ValueError("official target must be Linux ELF x86-64")
    for pass_entry in matrix["passes"]:
        for evidence in pass_entry["evidence"]:
            if evidence.startswith("http"):
                continue
            if not (ROOT / evidence).exists():
                raise ValueError(f"missing evidence path: {evidence}")


def main() -> int:
    try:
        _check_version()
        _check_matrix(_load_matrix())
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"release contract failed: {exc}", file=sys.stderr)
        return 1
    print(f"release contract valid: {EXPECTED_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
