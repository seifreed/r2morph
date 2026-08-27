#!/usr/bin/env python3
"""Expand the declared pass support into an exhaustive matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def build_matrix(document: dict[str, Any]) -> dict[str, Any]:
    """Build one explicit cell for every pass, format, and architecture."""
    formats = tuple(document.get("formats", {}))
    architectures = tuple(document.get("architectures", {}))
    cells: list[dict[str, Any]] = []
    for mutation_pass in document.get("passes", []):
        name = mutation_pass["name"]
        supported_formats = set(mutation_pass.get("formats", []))
        supported_architectures = set(mutation_pass.get("architectures", []))
        for binary_format in formats:
            for architecture in architectures:
                covered = binary_format in supported_formats and architecture in supported_architectures
                cells.append(
                    {
                        "pass": name,
                        "format": binary_format,
                        "architecture": architecture,
                        "status": "evidenced" if covered else "not-supported",
                        "evidence": mutation_pass.get("evidence", []) if covered else [],
                    }
                )
    return {
        "dimensions": {
            "passes": [mutation_pass["name"] for mutation_pass in document.get("passes", [])],
            "formats": list(formats),
            "architectures": list(architectures),
        },
        "cell_count": len(cells),
        "cells": cells,
    }


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("support matrix must contain a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix", type=Path, default=Path("docs/support-matrix.json"), nargs="?")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write and args.check:
        parser.error("--write and --check are mutually exclusive")
    document = _load(args.matrix)
    expected = build_matrix(document)
    if args.check:
        if document.get("matrix") != expected:
            raise SystemExit("support matrix is missing an up-to-date exhaustive matrix")
    elif args.write:
        document["matrix"] = expected
        args.matrix.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    else:
        print(json.dumps(expected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
