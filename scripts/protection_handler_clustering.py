#!/usr/bin/env python3
"""Measure generic handler similarity across deterministic VM personalities."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from difflib import SequenceMatcher
from itertools import pairwise
from pathlib import Path

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme

_DEFAULT_SEED = 20260820
_DEFAULT_COUNT = 10
_MAX_SEEDS = 100
_HANDLER_PATTERN = re.compile(r"^h_(\d+):\n(.*?)(?=^h_\d+:|^vm_exit:)", re.MULTILINE | re.DOTALL)
_LABEL_PATTERN = re.compile(r"\b(?:h|opaque)_\d+\b")
_NUMBER_PATTERN = re.compile(r"(?<![A-Za-z_])(?:0x[0-9A-Fa-f]+|\d+)(?![A-Za-z_])")
_REGISTER_PATTERN = re.compile(r"\b(?:e?[abcd]x|e?[sd]i|e?bp|e?sp|r(?:[0-9]+|[abcd]x|[sd]i|bp|sp)[bwdq]?|xmm[0-9]+)\b")
_SIMILARITY_THRESHOLD = 0.8


def _handler_bodies(seed: int) -> list[str]:
    scheme = build_vm_scheme(randomness.Random(seed))
    assembly = _interpreter_asm(0, scheme, has_fp=True)
    return [match.group(2) for match in _HANDLER_PATTERN.finditer(assembly)]


def _normalise_body(body: str) -> tuple[str, ...]:
    instructions: list[str] = []
    for line in body.splitlines():
        instruction = line.strip()
        if not instruction or instruction.endswith(":"):
            continue
        instruction = _LABEL_PATTERN.sub("LABEL", instruction)
        instruction = _REGISTER_PATTERN.sub("REG", instruction)
        instruction = _NUMBER_PATTERN.sub("IMM", instruction)
        instructions.append(instruction)
    return tuple(instructions)


def _digest(signature: tuple[str, ...]) -> str:
    return hashlib.sha256("\n".join(signature).encode("ascii")).hexdigest()


def _nearest_similarities(source: list[tuple[str, ...]], candidates: list[tuple[str, ...]]) -> list[float]:
    return [
        max(SequenceMatcher(None, signature, candidate, autojunk=False).ratio() for candidate in candidates)
        for signature in source
    ]


def measure(first_seed: int = _DEFAULT_SEED, count: int = _DEFAULT_COUNT) -> dict[str, object]:
    if count < 1 or count > _MAX_SEEDS:
        raise ValueError(f"count must be between 1 and {_MAX_SEEDS}")
    seed_rows: list[dict[str, object]] = []
    all_signatures: list[str] = []
    all_normalised: list[list[tuple[str, ...]]] = []
    for seed in range(first_seed, first_seed + count):
        bodies = _handler_bodies(seed)
        normalised = [_normalise_body(body) for body in bodies]
        signatures = [_digest(signature) for signature in normalised]
        all_normalised.append(normalised)
        all_signatures.extend(signatures)
        seed_rows.append(
            {
                "seed": seed,
                "handler_count": len(signatures),
                "raw_unique_count": len({_digest((body,)) for body in bodies}),
                "normalised_unique_count": len(set(signatures)),
                "largest_normalised_cluster": Counter(signatures).most_common(1)[0][1] if signatures else 0,
            }
        )
    counts = Counter(all_signatures)
    repeated = sum(value for value in counts.values() if value > 1)
    nearest = [score for left, right in pairwise(all_normalised) for score in _nearest_similarities(left, right)]
    return {
        "schema_version": 1,
        "first_seed": first_seed,
        "seed_count": count,
        "seeds": seed_rows,
        "cross_seed_exact_normalised_match_rate": repeated / len(all_signatures) if all_signatures else 0.0,
        "cross_seed_normalised_cluster_count": sum(value > 1 for value in counts.values()),
        "cross_seed_largest_normalised_cluster": max(counts.values(), default=0),
        "cross_seed_nearest_similarity_mean": sum(nearest) / len(nearest) if nearest else 0.0,
        "cross_seed_nearest_similarity_max": max(nearest, default=0.0),
        "cross_seed_nearest_similarity_above_threshold": sum(score >= _SIMILARITY_THRESHOLD for score in nearest),
        "similarity_threshold": _SIMILARITY_THRESHOLD,
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
