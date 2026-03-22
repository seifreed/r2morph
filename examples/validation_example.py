#!/usr/bin/env python3
"""
Validation example for r2morph.

This example demonstrates validation capabilities:
1. Structural validation (binary integrity)
2. Runtime validation (behavior comparison)
3. Semantic validation (equivalence checking)
4. Custom validation configurations

Usage:
    python validation_example.py original.bin mutated.bin
"""

import json
import sys
from pathlib import Path

from r2morph import __version__
from r2morph.core.engine import MorphEngine
from r2morph.core.config import EngineConfig
from r2morph.validation import BinaryValidator
from r2morph.validation.validator import RuntimeComparisonConfig


def demo_structural_validation(original_path: Path, mutated_path: Path):
    """Example: Structural validation."""
    print("\n" + "=" * 60)
    print("Demo 1: Structural Validation")
    print("=" * 60)

    print("\nStructural validation checks:")
    print("  - Section headers valid")
    print("  - Entry points accessible")
    print("  - Import tables valid")
    print("  - Relocations resolvable")
    print()

    config = EngineConfig.create_default()

    with MorphEngine(config=config) as engine:
        engine.load_binary(original_path).analyze()

        # Run mutations
        engine.add_mutation("nop")
        engine.add_mutation("substitute")

        result = engine.run(validation_mode="structural")

        print(f"Structural validation result: {result.validation_status}")
        print(f"  Passed: {result.passes_passed}/{result.passes_total}")

        # Detailed validation info
        report = engine.build_report(result)
        struct_data = report.get("validation", {}).get("structural", {})

        print(f"  Checks performed: {struct_data.get('checks_performed', 'N/A')}")
        print(f"  Issues found: {struct_data.get('issues_count', 0)}")


def demo_runtime_validation(original_path: Path, mutated_path: Path):
    """Example: Runtime validation."""
    print("\n" + "=" * 60)
    print("Demo 2: Runtime Validation")
    print("=" * 60)

    print("\nRuntime validation compares:")
    print("  - Exit codes")
    print("  - Standard output")
    print("  - Standard error")
    print("  - File outputs (optional)")
    print()

    # Runtime validation requires test cases
    RuntimeComparisonConfig(
        timeout_seconds=10,
        compare_stdout=True,
        compare_stderr=True,
        compare_exit_code=True,
    )

    EngineConfig.create_default()

    # Note: Runtime validation requires a test corpus
    # corpus = Path("test_corpus.json")  # JSON test cases

    print("Runtime validation requires a test corpus.")
    print("Test corpus format:")
    print(
        json.dumps(
            {
                "test_cases": [
                    {
                        "name": "test_1",
                        "args": ["--help"],
                        "stdin": None,
                        "expected_exit_code": 0,
                    },
                    {
                        "name": "test_2",
                        "args": ["input.txt"],
                        "stdin": "test input",
                        "expected_stdout": "expected output\n",
                    },
                ]
            },
            indent=2,
        )
    )


def demo_semantic_validation(original_path: Path, mutated_path: Path):
    """Example: Semantic validation."""
    print("\n" + "=" * 60)
    print("Demo 3: Semantic Validation (Experimental)")
    print("=" * 60)

    print("\nSemantic validation uses:")
    print("  - Symbolic execution")
    print("  - Bounded-step verification")
    print("  - Observable comparison")
    print()

    config = EngineConfig.create_default()

    with MorphEngine(config=config) as engine:
        engine.load_binary(original_path).analyze()
        engine.add_mutation("nop")

        # Semantic validation is experimental
        # result = engine.run(validation_mode="symbolic")
        print("Note: Semantic validation requires symbolic execution support.")
        print("      Use --allow-limited-symbolic for partial support.")


def demo_binary_validator(original_path: Path):
    """Example: Using BinaryValidator directly."""
    print("\n" + "=" * 60)
    print("Demo 4: Low-Level BinaryValidator")
    print("=" * 60)

    print("\nBinaryValidator provides direct validation:")
    print()

    # Create validator
    validator = BinaryValidator(original_path)

    # Check various aspects
    print("Running validation checks:")

    # Section validation
    sections_valid = validator.validate_sections()
    print(f"  Sections valid: {sections_valid}")

    # Header validation
    headers_valid = validator.validate_headers()
    print(f"  Headers valid: {headers_valid}")

    # Entry point validation
    entry_valid = validator.validate_entry_point()
    print(f"  Entry point valid: {entry_valid}")

    # Overall validity
    is_valid = validator.is_valid()
    print(f"\nOverall valid: {is_valid}")


def demo_validation_report(original_path: Path):
    """Example: Generating validation reports."""
    print("\n" + "=" * 60)
    print("Demo 5: Validation Reports")
    print("=" * 60)

    config = EngineConfig.create_default()

    with MorphEngine(config=config) as engine:
        engine.load_binary(original_path).analyze()
        engine.add_mutation("nop")

        result = engine.run(
            validation_mode="structural",
            rollback_policy="skip-invalid-pass",
        )

        # Generate detailed report
        report = engine.build_report(result)

        # Extract validation section
        validation = report.get("validation", {})

        print("\nValidation Report Structure:")
        print("  structural: Binary structure checks")
        print("  runtime: Runtime comparison results")
        print("  symbolic: Symbolic validation results")
        print()

        # Show structural details
        structural = validation.get("structural", {})
        print("Structural validation:")
        print(f"  Status: {structural.get('status', 'N/A')}")

        issues = structural.get("issues", [])
        if issues:
            print(f"  Issues ({len(issues)}):")
            for issue in issues[:3]:
                print(f"    - {issue.get('type', 'unknown')}: {issue.get('message', '')}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.bin> [mutated.bin]")
        print()
        print("Demonstrates validation capabilities:")
        print("  1. Structural validation")
        print("  2. Runtime validation")
        print("  3. Semantic validation")
        print("  4. BinaryValidator API")
        print("  5. Validation reports")
        sys.exit(1)

    original_path = Path(sys.argv[1])
    mutated_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    if not original_path.exists():
        print(f"Error: Input file not found: {original_path}")
        sys.exit(1)

    print(f"r2morph {__version__} - Validation Example")
    print("=" * 60)

    demo_structural_validation(original_path, mutated_path or original_path)
    demo_runtime_validation(original_path, mutated_path or original_path)
    demo_semantic_validation(original_path, mutated_path or original_path)
    demo_binary_validator(original_path)
    demo_validation_report(original_path)

    print("\n" + "=" * 60)
    print("Validation demos completed!")


if __name__ == "__main__":
    main()
