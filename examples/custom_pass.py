#!/usr/bin/env python3
"""
Custom mutation pass example for r2morph.

This example demonstrates creating custom mutation passes:
1. Extending MutationPass base class
2. Implementing apply method
3. Tracking mutations properly
4. Supporting configuration

Usage:
    python custom_pass.py input.bin output.bin
"""

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from r2morph import __version__
from r2morph.core.binary import Binary
from r2morph.core.config import EngineConfig
from r2morph.core.engine import MorphEngine
from r2morph.mutations.base import MutationPass, MutationRecord, MutationResult


@dataclass
class CustomNopConfig:
    """Configuration for custom NOP pass."""

    max_nops: int = 10
    probability: float = 0.5
    seed: int | None = None


class CustomNopPass(MutationPass):
    """
    Example custom mutation pass that inserts NOP instructions.

    This demonstrates how to create a custom mutation pass by:
    1. Extending MutationPass
    2. Implementing the apply() method
    3. Returning proper MutationResult

    Attributes:
        name: Pass identifier
        architectures: Supported architectures
        formats: Supported binary formats
    """

    name = "custom_nop"
    architectures = ("x86_64", "arm64")
    formats = ("elf", "pe", "mach-o")

    def __init__(self, config: CustomNopConfig | None = None):
        """
        Initialize custom NOP pass.

        Args:
            config: Pass configuration options
        """
        self.config = config or CustomNopConfig()
        self._records: list[MutationRecord] = []

    def apply(self, binary: Binary, context: dict[str, Any] | None = None) -> MutationResult:
        """
        Apply custom NOP insertion.

        Args:
            binary: Binary to mutate
            context: Optional context from previous passes

        Returns:
            MutationResult with mutation count and records
        """
        import random

        if self.config.seed is not None:
            random.seed(self.config.seed)

        self._records = []
        mutations_applied = 0

        # Process each function
        for func in binary.functions:
            if mutations_applied >= self.config.max_nops:
                break

            # Check if we should insert
            if random.random() > self.config.probability:
                continue

            # Find safe insertion points
            for instr in func.instructions:
                if mutations_applied >= self.config.max_nops:
                    break

                # Skip branch targets
                if instr.address in binary.branch_targets:
                    continue

                # Insert NOP
                record = MutationRecord(
                    address=instr.address,
                    pass_name=self.name,
                    description=f"Inserted NOP at 0x{instr.address:x}",
                )
                self._records.append(record)
                mutations_applied += 1

        return MutationResult(
            pass_name=self.name,
            successful=True,
            mutations_applied=mutations_applied,
            records=self._records,
            metadata={"config": self.config.__dict__},
        )


def demo_custom_pass(input_path: Path, output_path: Path):
    """Example: Using a custom mutation pass."""
    print("\n" + "=" * 60)
    print("Custom Mutation Pass Example")
    print("=" * 60)

    # Create configuration
    custom_config = CustomNopConfig(
        max_nops=5,
        probability=0.3,
        seed=42,  # Reproducible
    )

    print(f"\nConfiguration:")
    print(f"  Max NOPs: {custom_config.max_nops}")
    print(f"  Probability: {custom_config.probability}")
    print(f"  Seed: {custom_config.seed}")

    # Create pass instance
    custom_pass = CustomNopPass(config=custom_config)

    # Use with engine
    engine_config = EngineConfig.create_default()

    with MorphEngine(config=engine_config) as engine:
        engine.load_binary(input_path).analyze()

        # Add custom pass directly
        engine.add_mutation_pass(custom_pass)

        result = engine.run(validation_mode="off")

        print(f"\nResults:")
        print(f"  Mutations: {result.mutations_applied}")

        # Show records
        for record in custom_pass._records[:3]:
            print(f"  - 0x{record.address:x}: {record.description}")

        engine.save(output_path)
        print(f"\nSaved: {output_path}")


def demo_pass_composition(input_path: Path):
    """Example: Combining custom pass with built-in passes."""
    print("\n" + "=" * 60)
    print("Pass Composition Example")
    print("=" * 60)

    custom_config = CustomNopConfig(max_nops=3, probability=0.5)
    custom_pass = CustomNopPass(config=custom_config)

    engine_config = EngineConfig.create_default()

    with MorphEngine(config=engine_config) as engine:
        engine.load_binary(input_path).analyze()

        # Mix custom and built-in passes
        engine.add_mutation("nop")  # Built-in NOP insertion
        engine.add_mutation_pass(custom_pass)  # Custom pass
        engine.add_mutation("substitute")  # Built-in substitution

        result = engine.run(validation_mode="structural")

        print(f"\nComposed passes:")
        print(f"  Built-in: nop, substitute")
        print(f"  Custom: custom_nop")
        print(f"  Results: {result.mutations_applied} mutations")
        print(f"  Status: {result.validation_status}")


def demo_pass_dependencies():
    """Example: Understanding pass dependencies."""
    print("\n" + "=" * 60)
    print("Pass Dependencies")
    print("=" * 60)

    print("""
Pass execution order matters:

    Recommended order:
    1. register       - Safe, preserves semantics
    2. substitute     - Replaces instructions
    3. nop           - Inserts at safe locations
    4. expand        - Expands instruction sequences
    5. block         - Reorders basic blocks
    6. dead-code     - Adds dead code
    7. opaque        - Adds control flow
    8. cff           - Flattens control flow

    Passes can conflict:
    - substitute after register may miss optimization opportunities
    - block after dead-code may break dead code isolation
    - cff should always be last

    Use rollback_policy to handle conflicts:
    - fail-fast: Stop on first failure
    - skip-invalid-pass: Skip failing passes
    - skip-invalid-mutation: Skip failing mutations
""")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.bin> [output.bin]")
        print()
        print("Demonstrates custom mutation passes:")
        print("  1. Creating custom MutationPass")
        print("  2. Using with MorphEngine")
        print("  3. Pass composition")
        print("  4. Pass dependencies")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else input_path.with_suffix(".out")

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    print(f"r2morph {__version__} - Custom Pass Example")
    print("=" * 60)

    demo_custom_pass(input_path, output_path)
    demo_pass_composition(input_path)
    demo_pass_dependencies()

    print("\n" + "=" * 60)
    print("Custom pass examples completed!")


if __name__ == "__main__":
    main()
