#!/usr/bin/env python3
"""
Mutation workflow example for r2morph.

This example demonstrates working with different mutation passes:
1. Using individual mutation passes
2. Combining passes in a pipeline
3. Controlling pass configuration
4. Checking mutation results

Usage:
    python mutation_workflow.py input.bin
"""

import sys
from pathlib import Path

from r2morph import __version__
from r2morph.core.config import (
    EngineConfig,
    NopInsertionConfig,
    InstructionSubstitutionConfig,
    RegisterSubstitutionConfig,
)
from r2morph.core.engine import MorphEngine


def demo_individual_passes(input_path: Path):
    """Example: Using individual mutation passes."""
    print("\n" + "=" * 60)
    print("Demo 1: Individual Mutation Passes")
    print("=" * 60)

    config = EngineConfig.create_default()

    with MorphEngine(config=config) as engine:
        engine.load_binary(input_path).analyze()

        # Demo NOP insertion only
        print("\n[NOP Insertion Pass]")
        engine.add_mutation("nop")

        result = engine.run(validation_mode="off")
        print(f"  Mutations: {result.mutations_applied}")

        # Get mutation details from report
        report = engine.build_report(result)
        for pass_name, pass_result in report.get("passes", {}).items():
            print(f"  Pass: {pass_name}")
            print(f"    Mutations: {pass_result.get('mutation_count', 0)}")


def demo_custom_config(input_path: Path):
    """Example: Custom pass configuration."""
    print("\n" + "=" * 60)
    print("Demo 2: Custom Pass Configuration")
    print("=" * 60)

    # Create custom configurations for each pass
    nop_config = NopInsertionConfig(
        max_nop_sequences=5,
        probability=0.3,
    )

    substitute_config = InstructionSubstitutionConfig(
        preserve_semantics=True,
        max_instruction_size=15,
    )

    register_config = RegisterSubstitutionConfig(
        preserve_calling_convention=True,
    )

    config = EngineConfig(
        nop=nop_config,
        substitution=substitute_config,
        register=register_config,
    )

    with MorphEngine(config=config) as engine:
        engine.load_binary(input_path).analyze()

        engine.add_mutation("nop")
        engine.add_mutation("substitute")

        result = engine.run(validation_mode="structural")
        print("\nCustom configuration applied:")
        print(f"  NOP config: max={nop_config.max_nop_sequences}, prob={nop_config.probability}")
        print(f"  Result: {result.mutations_applied} mutations")


def demo_aggressive_mode(input_path: Path):
    """Example: Aggressive mutation mode."""
    print("\n" + "=" * 60)
    print("Demo 3: Aggressive Mutation Mode")
    print("=" * 60)

    # Aggressive mode enables more mutations per pass
    config = EngineConfig.create_aggressive()

    with MorphEngine(config=config) as engine:
        engine.load_binary(input_path).analyze()

        # All stable passes
        engine.add_mutation("nop")
        engine.add_mutation("substitute")
        engine.add_mutation("register")

        result = engine.run(validation_mode="structural")

        print("\nAggressive mode:")
        print(f"  Mutations: {result.mutations_applied}")
        print(f"  Validation: {result.validation_status}")


def demo_experimental_passes(input_path: Path):
    """Example: Experimental mutation passes."""
    print("\n" + "=" * 60)
    print("Demo 4: Experimental Passes")
    print("=" * 60)

    print("\nExperimental passes (best-effort support):")
    print("  - block: Basic block reordering")
    print("  - expand: Instruction expansion")
    print("  - cff: Control flow flattening")
    print("  - opaque: Opaque predicates")
    print("  - dead-code: Dead code injection")
    print()

    config = EngineConfig.create_default()

    with MorphEngine(config=config) as engine:
        engine.load_binary(input_path).analyze()

        # Note: Experimental passes may not work on all binaries
        engine.add_mutation("block")  # Experimental

        try:
            result = engine.run(
                validation_mode="structural",
                rollback_policy="skip-invalid-pass",
            )
            print(f"Experimental pass result: {result.validation_status}")
        except Exception as e:
            print(f"Experimental pass failed (expected): {e}")


def demo_mutation_records(input_path: Path):
    """Example: Accessing mutation records."""
    print("\n" + "=" * 60)
    print("Demo 5: Mutation Records")
    print("=" * 60)

    config = EngineConfig.create_default()

    with MorphEngine(config=config) as engine:
        engine.load_binary(input_path).analyze()
        engine.add_mutation("nop")

        result = engine.run(validation_mode="off")

        # Access mutation records
        report = engine.build_report(result)

        print("\nMutation Records:")
        for pass_name, pass_data in report.get("passes", {}).items():
            records = pass_data.get("records", [])
            print(f"\n  Pass: {pass_name}")
            print(f"  Record count: {len(records)}")

            # Show first few records
            for i, record in enumerate(records[:3]):
                addr = record.get("address", "N/A")
                desc = record.get("description", "N/A")
                print(f"    [{i}] 0x{addr:x}: {desc}")

            if len(records) > 3:
                print(f"    ... and {len(records) - 3} more")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.bin>")
        print()
        print("Demonstrates various mutation workflows:")
        print("  1. Individual passes")
        print("  2. Custom configuration")
        print("  3. Aggressive mode")
        print("  4. Experimental passes")
        print("  5. Mutation records")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    print(f"r2morph {__version__} - Mutation Workflow Example")
    print("=" * 60)

    demo_individual_passes(input_path)
    demo_custom_config(input_path)
    demo_aggressive_mode(input_path)
    demo_experimental_passes(input_path)
    demo_mutation_records(input_path)

    print("\n" + "=" * 60)
    print("Demos completed!")


if __name__ == "__main__":
    main()
