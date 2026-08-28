#!/usr/bin/env python3
"""Build a bounded, fixture-backed virtualization coverage inventory."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_FIXTURE_PATTERN = re.compile(r"^elf_vm_(?P<name>.+)_x86_64$")
_CAPABILITY_PATTERNS: dict[str, tuple[str, ...]] = {
    "gp_arithmetic": ("arith", "bigimm", "movabs", "word16", "imul", "div", "incdec", "not", "bswap"),
    "memory_addressing": ("mem", "movidx", "movx", "lea", "riprel", "global"),
    "flags_and_conditions": ("flag", "bool", "cmp", "setcc", "cmov", "bt", "shift", "rotate", "isa"),
    "calls_and_returns": ("call", "incall", "mcall", "multiret"),
    "floating_point_and_simd": ("fp", "simd", "fparith", "fpmov", "fpcmp", "fppacked"),
    "stack_and_abi": ("prologue", "push", "pop", "leave", "redzone", "varargs"),
    "control_flow_and_dispatch": ("interp", "switch", "pie", "multiexit"),
    "thread_runtime_boundaries": ("dynamic", "tls", "thread", "signal"),
    "signals_and_system_calls": ("syscall",),
    "unsupported_boundaries": ("fallback", "flaglive", "movtorsp"),
}


def _capabilities_for_fixture(stem: str) -> tuple[str, ...]:
    match = _FIXTURE_PATTERN.fullmatch(stem)
    if match is None:
        return ()
    name = match.group("name")
    return tuple(
        capability
        for capability, tokens in _CAPABILITY_PATTERNS.items()
        if not (capability == "calls_and_returns" and "syscall" in name) and any(token in name for token in tokens)
    )


def build_coverage_inventory(dataset: Path) -> dict[str, object]:
    """Return fixture coverage without retaining binary contents."""
    fixtures = sorted(path for path in dataset.iterdir() if path.is_file() and _FIXTURE_PATTERN.fullmatch(path.name))
    by_capability: dict[str, list[str]] = {capability: [] for capability in _CAPABILITY_PATTERNS}
    unclassified: list[str] = []
    for fixture in fixtures:
        capabilities = _capabilities_for_fixture(fixture.name)
        if not capabilities:
            unclassified.append(fixture.name)
        for capability in capabilities:
            by_capability[capability].append(fixture.name)

    return {
        "schema_version": 1,
        "scope": "elf-x86-64-virtualization-fixtures",
        "fixture_count": len(fixtures),
        "capabilities": {
            capability: {"fixture_count": len(names), "fixtures": names} for capability, names in by_capability.items()
        },
        "unclassified": unclassified,
        "covered_capability_count": sum(bool(names) for names in by_capability.values()),
        "capability_count": len(by_capability),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = build_coverage_inventory(args.dataset)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
