#!/usr/bin/env python3
"""Record reproducible virtualization and semantic baseline measurements."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure(fixture: Path, seeds: range) -> dict[str, object]:
    baseline_exit = emulate_exit_code(fixture)
    runs: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="r2morph-maturity-") as temp_dir:
        for seed in seeds:
            output = Path(temp_dir) / str(seed)
            shutil.copy(fixture, output)
            binary = Binary(output, writable=True)
            binary.open()
            try:
                stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": seed}).apply(binary)
                binary.save()
            finally:
                binary.close()
            runs.append(
                {
                    "seed": seed,
                    "output_sha256": sha256(output),
                    "output_size": output.stat().st_size,
                    "functions_virtualized": stats["functions_virtualized"],
                    "total_instructions": stats["total_instructions"],
                    "total_bytecode_bytes": stats["total_bytecode_bytes"],
                    "semantic_exit": emulate_exit_code(output),
                }
            )
    return {
        "fixture": str(fixture),
        "format": "ELF",
        "architecture": "x86_64",
        "baseline_sha256": sha256(fixture),
        "baseline_size": fixture.stat().st_size,
        "baseline_exit": baseline_exit,
        "seeds": [run["seed"] for run in runs],
        "runs": runs,
        "all_semantic_equal": all(run["semantic_exit"] == baseline_exit for run in runs),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--first-seed", type=int, default=20260820)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = measure(args.fixture, range(args.first_seed, args.first_seed + args.count))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
