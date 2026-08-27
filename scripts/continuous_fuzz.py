#!/usr/bin/env python3
"""Run deterministic parser and rewrite-planning fuzz campaigns."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from r2morph.devirtualization.binary_rewriter_models import CodePatch, RewriteOperation
from r2morph.devirtualization.binary_rewriter_planning import calculate_address_shifts, plan_rewrite_strategy
from r2morph.platform.elf_handler_parsing import parse_elf_header
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler_parsing import read_pe_header

_DEFAULT_CASES = 1000
_DEFAULT_MAX_PAYLOAD = 4096
_MAX_FAILURES = 128


def _bounded_value(seed: int, index: int, slot: int, maximum: int) -> int:
    digest = hashlib.sha256(f"{seed}:{index}:{slot}".encode("ascii")).digest()
    return int.from_bytes(digest[:8], "little") % (maximum + 1)


def _payload(seed: int, index: int, maximum: int) -> bytes:
    size = _bounded_value(seed, index, 0, maximum)
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(f"{seed}:{index}:{counter}".encode("ascii")).digest())
        counter += 1
    return bytes(output[:size])


def _rewrite_case(seed: int, index: int) -> None:
    patches = [
        CodePatch(
            address=_bounded_value(seed, index, patch_index, 0xFF000) + 0x1000,
            operation=RewriteOperation.INSTRUCTION_REPLACE,
            original_bytes=b"\x90",
            new_bytes=_payload(seed, index + patch_index, 32),
            size_change=_bounded_value(seed, index, patch_index + 8, 64) - 32,
        )
        for patch_index in range(index % 8)
    ]
    plan_rewrite_strategy(patches)
    calculate_address_shifts(patches)


def _exercise_case(payload: bytes, seed: int, index: int) -> None:
    with tempfile.TemporaryDirectory(prefix="r2morph-fuzz-") as directory:
        path = Path(directory) / "candidate"
        path.write_bytes(payload)
        parse_elf_header(path)
        read_pe_header(path)
        MachOHandler(path)._parse_macho_basic()
    _rewrite_case(seed, index)


def run_campaign(
    cases: int = _DEFAULT_CASES, seed: int = 20260827, max_payload: int = _DEFAULT_MAX_PAYLOAD
) -> dict[str, object]:
    """Exercise all parser and rewrite targets with bounded generated inputs."""
    if cases < 1:
        raise ValueError("cases must be positive")
    if max_payload < 1:
        raise ValueError("max_payload must be positive")

    failures: list[dict[str, object]] = []
    for index in range(cases):
        payload = _payload(seed, index, max_payload)
        try:
            _exercise_case(payload, seed, index)
        except Exception as error:  # Fuzz boundary records unexpected parser failures for triage.
            if len(failures) < _MAX_FAILURES:
                failures.append(
                    {
                        "case": index,
                        "input_sha256": hashlib.sha256(payload).hexdigest(),
                        "input_size": len(payload),
                        "error_type": type(error).__name__,
                    }
                )

    return {
        "schema_version": 1,
        "seed": seed,
        "cases": cases,
        "max_payload": max_payload,
        "failures": failures,
        "failure_count": len(failures),
        "failure_limit": _MAX_FAILURES,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=_DEFAULT_CASES)
    parser.add_argument("--seed", type=int, default=20260827)
    parser.add_argument("--max-payload", type=int, default=_DEFAULT_MAX_PAYLOAD)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run_campaign(args.cases, args.seed, args.max_payload)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["failure_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
