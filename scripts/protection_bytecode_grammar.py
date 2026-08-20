#!/usr/bin/env python3
"""Measure per-instance bytecode padding and handler stride variation."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme

_DEFAULT_SEED = 20260820
_DEFAULT_COUNT = 10
_MAX_SEEDS = 100
_HANDLER_PATTERN = re.compile(r"^h_(\d+):\n(.*?)(?=^h_\d+:|^vm_exit:)", re.MULTILINE | re.DOTALL)
_STRIDE_PATTERN = re.compile(r"add rsi, (\d+)")
_TARGET_OPERATION = ("mov", False, 64)


def _handler_strides(seed: int) -> tuple[dict[int, tuple[str, bool, int]], dict[int, int], tuple[int, ...]]:
    scheme = build_vm_scheme(randomness.Random(seed))
    index_to_key = {index: key for key, indices in scheme.dup.items() for index in indices}
    assembly = _interpreter_asm(0, scheme, has_fp=True)
    strides = {
        int(match.group(1)): int(_STRIDE_PATTERN.findall(match.group(2))[-1])
        for match in _HANDLER_PATTERN.finditer(assembly)
    }
    padding = scheme.record_padding or (0,) * len(index_to_key)
    return index_to_key, strides, padding


def measure(first_seed: int = _DEFAULT_SEED, count: int = _DEFAULT_COUNT) -> dict[str, object]:
    if count < 1 or count > _MAX_SEEDS:
        raise ValueError(f"count must be between 1 and {_MAX_SEEDS}")

    padding_counts: Counter[int] = Counter()
    target_strides: list[int] = []
    all_strides: list[int] = []
    seed_rows: list[dict[str, object]] = []
    for seed in range(first_seed, first_seed + count):
        index_to_key, strides, padding = _handler_strides(seed)
        padding_counts.update(padding)
        all_strides.extend(strides.values())
        target = [strides[index] for index, key in index_to_key.items() if key == _TARGET_OPERATION]
        target_strides.extend(target)
        seed_rows.append(
            {
                "seed": seed,
                "handler_count": len(index_to_key),
                "target_handler_count": len(target),
                "target_stride_values": sorted(set(target)),
                "padding_bytes": sum(padding),
                "padding_histogram": {str(value): padding.count(value) for value in sorted(set(padding))},
            }
        )

    total_handlers = sum(int(row["handler_count"]) for row in seed_rows)
    return {
        "schema_version": 1,
        "first_seed": first_seed,
        "seed_count": count,
        "target_operation": {"mnemonic": "mov", "is_immediate": False, "width": 64},
        "seeds": seed_rows,
        "total_handlers": total_handlers,
        "total_padding_bytes": sum(value * count for value, count in padding_counts.items()),
        "padding_histogram": {str(value): count for value, count in sorted(padding_counts.items())},
        "mean_padding_bytes_per_handler": sum(value * count for value, count in padding_counts.items())
        / total_handlers,
        "all_handler_stride_values": sorted(set(all_strides)),
        "target_stride_values": sorted(set(target_strides)),
        "target_stride_mean": sum(target_strides) / len(target_strides),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--first-seed", type=int, default=_DEFAULT_SEED)
    parser.add_argument("--count", type=int, default=_DEFAULT_COUNT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = measure(args.first_seed, args.count)
    except ValueError as error:
        parser.error(str(error))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
