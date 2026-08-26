#!/usr/bin/env python3
"""Run the repository's own VM recovery logic as a bounded adversary."""

from __future__ import annotations

import argparse
import json
from itertools import pairwise
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer
from r2morph.devirtualization.vm_handler_models import VMArchitecture
from tests.integration.elf_emulator import trace_execution

_MAX_DYNAMIC_EVENTS = 256


def _classify(binary: Binary, address: int, architecture: VMArchitecture) -> str:
    if architecture.handler_table_address and architecture.handlers:
        return "recovered_handler_table"
    instructions = binary.get_function_disasm(address)
    text = " ".join(str(instruction.get("disasm", "")) for instruction in instructions).lower()
    if "jmp rax" in text or "jmp [" in text:
        return "unsupported_indirect_dispatch"
    return "no_vm_candidate"


def _dynamic_recovery(path: Path) -> dict[str, object]:
    """Summarize bounded runtime recovery without retaining payload bytes."""
    trace = trace_execution(path)
    raw_jumps = trace.get("indirect_jumps", [])
    if not isinstance(raw_jumps, list):
        return {"status": trace.get("status"), "error": trace.get("error"), "recovered": False}

    correlated: list[dict[str, int]] = []
    for jump in raw_jumps[:_MAX_DYNAMIC_EVENTS]:
        if not isinstance(jump, dict):
            continue
        fields = ("target", "vpc", "bytecode_base", "position")
        if not all(isinstance(jump.get(field), int) for field in fields):
            continue
        if jump["bytecode_base"] <= 0:
            continue
        correlated.append({field: int(jump[field]) for field in fields})

    positions = [event["position"] for event in correlated]
    positive_deltas = {current - previous for previous, current in pairwise(positions) if current > previous}
    raw_position_matches = [event for event in correlated if event["vpc"] - event["bytecode_base"] == event["position"]]
    targets = [event["target"] for event in correlated]
    return {
        "status": trace.get("status"),
        "error": trace.get("error"),
        "recovered": bool(raw_position_matches),
        "correlated_dispatch_count": len(correlated),
        "raw_position_match_count": len(raw_position_matches),
        "state_encoding_detected": bool(correlated) and len(raw_position_matches) < len(correlated),
        "unique_handler_targets": len(set(targets)),
        "unique_bytecode_positions": len(set(positions)),
        "observed_positive_position_deltas": sorted(positive_deltas),
        "handler_target_sequence": targets[:_MAX_DYNAMIC_EVENTS],
    }


def analyze(path: Path, limit: int) -> dict[str, object]:
    binary = Binary(path)
    binary.open()
    try:
        binary.analyze("aa")
        functions = sorted(binary.get_functions(), key=lambda item: int(item.get("size", 0)), reverse=True)[:limit]
        rows: list[dict[str, object]] = []
        for function in functions:
            address = function.get("addr")
            if not isinstance(address, int):
                continue
            architecture = VMHandlerAnalyzer(binary).analyze_vm_architecture(address)
            rows.append(
                {
                    "address": address,
                    "function_size": function.get("size", 0),
                    "classification": _classify(binary, address, architecture),
                    "handler_table_address": architecture.handler_table_address,
                    "handler_count": len(architecture.handlers),
                    "bytecode_address": architecture.bytecode_address,
                    "vm_registers": architecture.vm_registers,
                    "vm_context_size": architecture.vm_context_size,
                }
            )
        return {
            "sample": path.name,
            "functions_examined": len(rows),
            "results": rows,
            "dynamic_recovery": _dynamic_recovery(path),
        }
    finally:
        binary.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--limit", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")
    rendered = json.dumps(analyze(args.fixture, args.limit), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
