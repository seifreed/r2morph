"""Isolated worker for one benchmark mutation and its binary analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.adversarial_benchmark_tools import _protected_copy_worker


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("directory", type=Path)
    parser.add_argument("pass_name")
    parser.add_argument("progress", type=Path)
    parser.add_argument("result", type=Path)
    arguments = parser.parse_args()
    _, pass_row = _protected_copy_worker(
        arguments.original,
        arguments.directory,
        arguments.pass_name,
        arguments.progress,
    )
    arguments.result.write_text(json.dumps(pass_row), encoding="utf-8")


if __name__ == "__main__":
    main()
