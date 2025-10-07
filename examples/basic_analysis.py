#!/usr/bin/env python3
"""
Basic example of using r2morph to analyze a binary.

This example demonstrates:
1. Loading a binary with r2pipe
2. Running analysis
3. Listing functions
4. Getting basic statistics

Usage:
    python examples/basic_analysis.py /path/to/binary
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from r2morph import Binary


def main():
    if len(sys.argv) < 2:
        print("Usage: python basic_analysis.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]

    print(f"Analyzing binary: {binary_path}\n")

    with Binary(binary_path) as binary:
        print("[+] Running analysis...")
        binary.analyze(level="aaa")

        arch_info = binary.get_arch_info()
        print("\n=== Architecture Information ===")
        print(f"  Architecture: {arch_info['arch']}")
        print(f"  Bits:         {arch_info['bits']}")
        print(f"  Endian:       {arch_info['endian']}")
        print(f"  Format:       {arch_info['format']}")

        functions = binary.get_functions()
        print(f"\n=== Functions ({len(functions)} total) ===")

        for i, func in enumerate(functions[:20]):
            name = func.get("name", "unknown")
            addr = func.get("offset", 0)
            size = func.get("size", 0)
            print(f"  {i + 1:3d}. 0x{addr:08x} | {size:5d} bytes | {name}")

        if len(functions) > 20:
            print(f"  ... and {len(functions) - 20} more functions")

        if functions:
            first_func = functions[0]
            addr = first_func.get("offset", 0)
            name = first_func.get("name", "unknown")

            print(f"\n=== First Function Disassembly: {name} ===")
            disasm = binary.get_function_disasm(addr)

            for i, insn in enumerate(disasm[:10]):
                insn_addr = insn.get("offset", 0)
                insn_disasm = insn.get("disasm", "")
                insn_bytes = insn.get("bytes", "")
                print(f"  0x{insn_addr:08x}  {insn_bytes:16s}  {insn_disasm}")

            if len(disasm) > 10:
                print(f"  ... and {len(disasm) - 10} more instructions")

        print("\n[+] Analysis complete!")


if __name__ == "__main__":
    main()
