#!/usr/bin/env python3
"""Run the repository's own VM recovery logic as a bounded adversary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer
from r2morph.devirtualization.vm_handler_models import VMArchitecture


def _classify(binary: Binary, address: int, architecture: VMArchitecture) -> str:
    if architecture.handler_table_address and architecture.handlers:
        return "recovered_handler_table"
    instructions = binary.get_function_disasm(address)
    text = " ".join(str(instruction.get("disasm", "")) for instruction in instructions).lower()
    if "jmp rax" in text or "jmp [" in text:
        return "unsupported_indirect_dispatch"
    return "no_vm_candidate"


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
        return {"sample": path.name, "functions_examined": len(rows), "results": rows}
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
