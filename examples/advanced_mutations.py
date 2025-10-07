#!/usr/bin/env python3
"""
Advanced mutations example for r2morph.

Demonstrates all available mutation passes:
1. NOP insertion
2. Instruction substitution
3. Block reordering
4. Register substitution
5. Instruction expansion

Usage:
    python examples/advanced_mutations.py <binary_path> [output_path]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from r2morph import MorphEngine
from r2morph.mutations import (
    BlockReorderingPass,
    InstructionExpansionPass,
    InstructionSubstitutionPass,
    NopInsertionPass,
    RegisterSubstitutionPass,
)
from r2morph.utils.logging import setup_logging


def demo_individual_mutations(binary_path: Path):
    """
    Demonstrate each mutation pass individually.
    """
    print("\n" + "=" * 70)
    print("DEMONSTRATING INDIVIDUAL MUTATION PASSES")
    print("=" * 70)

    mutations = [
        (
            "NOP Insertion",
            NopInsertionPass(
                {
                    "max_nops_per_function": 5,
                    "probability": 0.3,
                }
            ),
        ),
        (
            "Instruction Substitution",
            InstructionSubstitutionPass(
                {
                    "max_substitutions_per_function": 3,
                    "probability": 0.2,
                }
            ),
        ),
        (
            "Block Reordering",
            BlockReorderingPass(
                {
                    "probability": 0.3,
                    "max_functions": 5,
                }
            ),
        ),
        (
            "Register Substitution",
            RegisterSubstitutionPass(
                {
                    "probability": 0.2,
                    "max_substitutions_per_function": 3,
                }
            ),
        ),
        (
            "Instruction Expansion",
            InstructionExpansionPass(
                {
                    "probability": 0.2,
                    "max_expansions_per_function": 5,
                }
            ),
        ),
    ]

    for name, mutation_pass in mutations:
        print(f"\n{name}")
        print("-" * 70)

        with MorphEngine() as engine:
            engine.load_binary(binary_path).analyze()
            engine.add_mutation(mutation_pass)
            result = engine.run()

            for _pass_name, pass_result in result.get("pass_results", {}).items():
                if "error" in pass_result:
                    print(f"  Error: {pass_result['error']}")
                else:
                    mutations_applied = pass_result.get("mutations_applied", 0)
                    functions_mutated = pass_result.get("functions_mutated", 0)

                    print(f"  Mutations applied: {mutations_applied}")
                    print(f"  Functions mutated: {functions_mutated}")

                    for key, value in pass_result.items():
                        if key not in ["mutations_applied", "functions_mutated", "total_functions"]:
                            print(f"  {key.replace('_', ' ').title()}: {value}")


def demo_combined_mutations(binary_path: Path, output_path: Path):
    """
    Demonstrate combining multiple mutation passes.
    """
    print("\n" + "=" * 70)
    print("DEMONSTRATING COMBINED MUTATION PASSES")
    print("=" * 70)
    print(f"\nInput:  {binary_path}")
    print(f"Output: {output_path}\n")

    with MorphEngine() as engine:
        engine.load_binary(binary_path).analyze()

        print("Adding mutation passes:")

        engine.add_mutation(
            NopInsertionPass(
                {
                    "max_nops_per_function": 10,
                    "probability": 0.4,
                }
            )
        )
        print("  [+] NOP Insertion")

        engine.add_mutation(
            InstructionSubstitutionPass(
                {
                    "max_substitutions_per_function": 5,
                    "probability": 0.3,
                }
            )
        )
        print("  [+] Instruction Substitution")

        engine.add_mutation(
            BlockReorderingPass(
                {
                    "probability": 0.25,
                    "max_functions": 15,
                }
            )
        )
        print("  [+] Block Reordering")

        engine.add_mutation(
            RegisterSubstitutionPass(
                {
                    "probability": 0.25,
                    "max_substitutions_per_function": 4,
                }
            )
        )
        print("  [+] Register Substitution")

        engine.add_mutation(
            InstructionExpansionPass(
                {
                    "probability": 0.2,
                    "max_expansions_per_function": 8,
                    "max_expansion_size": 4,
                }
            )
        )
        print("  [+] Instruction Expansion")

        print("\nApplying mutations...")
        result = engine.run()

        print("\n" + "=" * 70)
        print("RESULTS")
        print("=" * 70)
        print(f"\nTotal mutations applied: {result.get('total_mutations', 0)}")
        print(f"Passes run: {result.get('passes_run', 0)}")

        print("\nPer-pass breakdown:")
        for pass_name, pass_result in result.get("pass_results", {}).items():
            print(f"\n  {pass_name}:")
            if "error" in pass_result:
                print(f"    Error: {pass_result['error']}")
            else:
                for key, value in pass_result.items():
                    if isinstance(value, int | float | str):
                        print(f"    {key.replace('_', ' ').title()}: {value}")

        print(f"\nSaving morphed binary to: {output_path}")
        engine.save(output_path)

    print("\n[+] Combined mutation complete!")


def main():
    if len(sys.argv) < 2:
        print("Usage: python advanced_mutations.py <binary_path> [output_path]")
        sys.exit(1)

    binary_path = Path(sys.argv[1])

    if len(sys.argv) > 2:
        output_path = Path(sys.argv[2])
    else:
        output_path = binary_path.parent / f"{binary_path.stem}_morphed{binary_path.suffix}"

    setup_logging("INFO")

    print("=" * 70)
    print("r2morph - Advanced Mutations Example")
    print("=" * 70)

    demo_individual_mutations(binary_path)

    demo_combined_mutations(binary_path, output_path)

    print("\n" + "=" * 70)
    print("Done! Check the output file:")
    print(f"  {output_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
