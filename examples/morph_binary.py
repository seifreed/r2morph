#!/usr/bin/env python3
"""
Example of using r2morph to apply transformations to a binary.

This example demonstrates:
1. Loading and analyzing a binary
2. Adding mutation passes
3. Running the transformation pipeline
4. Saving the morphed binary

Usage:
    python examples/morph_binary.py /path/to/binary [output_path]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from r2morph import MorphEngine
from r2morph.mutations import InstructionSubstitutionPass, NopInsertionPass
from r2morph.utils.logging import setup_logging


def main():
    if len(sys.argv) < 2:
        print("Usage: python morph_binary.py <binary_path> [output_path]")
        sys.exit(1)

    binary_path = Path(sys.argv[1])
    output_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else binary_path.with_name(f"{binary_path.stem}_morphed{binary_path.suffix}")
    )

    setup_logging("INFO")

    print("=" * 60)
    print("r2morph - Metamorphic Binary Transformation Engine")
    print("=" * 60)
    print(f"\nInput:  {binary_path}")
    print(f"Output: {output_path}\n")

    with MorphEngine() as engine:
        print("[+] Loading and analyzing binary...")
        engine.load_binary(binary_path).analyze()

        print("[+] Adding mutation passes...")

        nop_config = {
            "max_nops_per_function": 5,
            "probability": 0.3,
        }
        engine.add_mutation(NopInsertionPass(config=nop_config))

        sub_config = {
            "max_substitutions_per_function": 3,
            "probability": 0.2,
        }
        engine.add_mutation(InstructionSubstitutionPass(config=sub_config))

        print("[+] Running transformation pipeline...\n")
        result = engine.run()

        print("\n" + "=" * 60)
        print("Transformation Results")
        print("=" * 60)
        print(f"Total mutations applied: {result.get('total_mutations', 0)}")
        print(f"Passes run:              {result.get('passes_run', 0)}")

        print("\nPer-pass results:")
        for pass_name, pass_result in result.get("pass_results", {}).items():
            print(f"\n  {pass_name}:")
            if "error" in pass_result:
                print(f"    Error: {pass_result['error']}")
            else:
                for key, value in pass_result.items():
                    print(f"    {key}: {value}")

        print(f"\n[+] Saving morphed binary to: {output_path}")
        engine.save(output_path)

        print("\n[+] Transformation complete!")


if __name__ == "__main__":
    main()
