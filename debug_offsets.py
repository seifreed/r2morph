#!/usr/bin/env python3
"""
Debug script to check what fields r2pipe returns for instructions.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from r2morph.core.binary import Binary


def debug_instructions(binary_path: str):
    """Check instruction fields."""
    print(f"Debugging instruction fields for: {binary_path}\n")

    with Binary(binary_path) as binary:
        binary.analyze()

        functions = binary.get_functions()
        print(f"Found {len(functions)} functions\n")

        if functions:
            func = functions[0]
            print(f"Function: {func.get('name', 'unknown')}")
            print(f"Address: 0x{func.get('addr', 0):x}")
            print(f"Size: {func.get('size', 0)}")
            print()

            instructions = binary.get_function_disasm(func["addr"])
            print("First 5 instructions:\n")

            for i, insn in enumerate(instructions[:5]):
                print(f"Instruction {i}:")
                print(json.dumps(insn, indent=2))
                print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_offsets.py <binary>")
        sys.exit(1)

    debug_instructions(sys.argv[1])
