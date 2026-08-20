#!/usr/bin/env python3
"""Record bounded dynamic evidence for a protected ELF fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tests.integration.elf_emulator import trace_execution


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {"sample": args.fixture.name, "trace": trace_execution(args.fixture)}
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
