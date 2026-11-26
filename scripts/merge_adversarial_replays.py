#!/usr/bin/env python3
"""Merge exact-hash analyzer replay reports into an adversarial corpus report."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import cast

from scripts.adversarial_benchmark import merge_adversarial_replay_reports


def _read_report(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read JSON report {path}: {type(error).__name__}") from error
    if not isinstance(value, dict):
        raise ValueError(f"report root must be a JSON object: {path}")
    return cast(dict[str, object], value)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True, help="merged corpus report to augment")
    parser.add_argument(
        "--replay", type=Path, action="append", required=True, help="single-pair analyzer replay report"
    )
    parser.add_argument("--output", type=Path, required=True, help="output merged corpus report")
    args = parser.parse_args(argv)
    try:
        merged = merge_adversarial_replay_reports(
            _read_report(args.base),
            [_read_report(path) for path in args.replay],
        )
    except ValueError as error:
        parser.error(str(error))
    rendered = json.dumps(merged, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(f"{args.output.suffix}.tmp-{os.getpid()}")
    try:
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print(json.dumps(merged["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
