#!/usr/bin/env python3
"""
Basic usage example for r2morph.

This example demonstrates the fundamental mutation workflow:
1. Load a binary
2. Apply mutation passes
3. Validate the result
4. Save the mutated binary

Usage:
    python basic_usage.py input.bin output.bin
"""

import json
import sys
from pathlib import Path

from r2morph import __version__
from r2morph.core.config import EngineConfig
from r2morph.core.engine import MorphEngine


def main(input_path: Path, output_path: Path):
    """
    Example: Apply stable mutations to a binary.

    This demonstrates the core r2morph workflow:
    - Load binary using MorphEngine
    - Apply mutation passes (nop insertion, instruction substitution, register substitution)
    - Validate structural integrity
    - Save mutated binary
    """
    print(f"r2morph {__version__} - Basic Usage Example")
    print("=" * 50)
    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")
    print()

    # Create configuration
    # EngineConfig.create_default() uses conservative mutation settings
    # EngineConfig.create_aggressive() enables more mutations
    config = EngineConfig.create_default()

    # Initialize engine with configuration
    with MorphEngine(config=config) as engine:
        # Step 1: Load and analyze binary
        print("[1/4] Loading binary...")
        engine.load_binary(input_path)
        engine.analyze()

        binary = engine.binary
        print(f"      Architecture: {binary.architecture}")
        print(f"      Format: {binary.format}")
        print(f"      Functions: {len(list(binary.functions))}")
        print()

        # Step 2: Add mutation passes
        # The stable mutation passes are: nop, substitute, register
        print("[2/4] Adding mutation passes...")
        engine.add_mutation("nop")
        engine.add_mutation("substitute")
        engine.add_mutation("register")
        print("      Added: nop, substitute, register")
        print()

        # Step 3: Run mutation pipeline with validation
        print("[3/4] Running mutation pipeline...")
        result = engine.run(
            validation_mode="structural",
            rollback_policy="skip-invalid-pass",
        )

        # Print results
        print(f"      Passes executed: {result.passes_executed}")
        print(f"      Mutations applied: {result.mutations_applied}")
        print(f"      Validation status: {result.validation_status}")
        print()

        # Step 4: Save mutated binary
        print("[4/4] Saving mutated binary...")
        engine.save(output_path)
        print(f"      Saved to: {output_path}")
        print()

        # Optional: Generate report
        report_path = output_path.with_suffix(".report.json")
        report = engine.build_report(result)
        report_path.write_text(json.dumps(report, indent=2))
        print(f"      Report: {report_path}")

    print()
    print("Done!")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.bin> <output.bin>")
        print()
        print("Example:")
        print(f"  {sys.argv[0]} /path/to/binary /path/to/output")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    main(input_path, output_path)
