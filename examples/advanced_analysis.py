#!/usr/bin/env python3
"""
Advanced analysis example for r2morph.

Demonstrates:
1. Control Flow Graph (CFG) analysis
2. Data dependency analysis
3. Invariant detection
4. Advanced mutation with validation

Usage:
    python examples/advanced_analysis.py /path/to/binary
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from r2morph import Binary
from r2morph.analysis import (
    CFGBuilder,
    DependencyAnalyzer,
    InvariantDetector,
    SemanticValidator,
)


def analyze_control_flow(binary: Binary):
    """Demonstrate CFG analysis."""
    print("\n" + "=" * 60)
    print("CONTROL FLOW GRAPH ANALYSIS")
    print("=" * 60)

    cfg_builder = CFGBuilder(binary)

    functions = binary.get_functions()[:5]

    for func in functions:
        addr = func.get("offset", 0)
        name = func.get("name", f"func_{addr:x}")

        print(f"\nAnalyzing function: {name} @ 0x{addr:x}")

        cfg = cfg_builder.build_cfg(addr, name)

        print(f"  Basic blocks: {len(cfg.blocks)}")
        print(f"  Edges: {len(cfg.edges)}")
        print(f"  Cyclomatic complexity: {cfg.get_complexity()}")

        loops = cfg.find_loops()
        if loops:
            print(f"  Loops found: {len(loops)}")
            for from_addr, to_addr in loops:
                print(f"    Loop: 0x{from_addr:x} -> 0x{to_addr:x}")

        dominators = cfg.compute_dominators()
        if dominators and cfg.entry_block:
            entry_doms = dominators.get(cfg.entry_block.address, set())
            print(f"  Entry block dominators: {len(entry_doms)}")


def analyze_dependencies(binary: Binary):
    """Demonstrate dependency analysis."""
    print("\n" + "=" * 60)
    print("DATA DEPENDENCY ANALYSIS")
    print("=" * 60)

    functions = binary.get_functions()[:3]

    for func in functions:
        addr = func.get("offset", 0)
        name = func.get("name", f"func_{addr:x}")

        print(f"\nAnalyzing dependencies in: {name} @ 0x{addr:x}")

        try:
            instructions = binary.get_function_disasm(addr)
        except Exception as e:
            print(f"  Error: {e}")
            continue

        dep_analyzer = DependencyAnalyzer()
        dependencies = dep_analyzer.analyze_dependencies(instructions)

        print(f"  Total instructions: {len(instructions)}")
        print(f"  Dependencies found: {len(dependencies)}")

        raw_deps = sum(1 for d in dependencies if d.dep_type.value == "RAW")
        war_deps = sum(1 for d in dependencies if d.dep_type.value == "WAR")
        waw_deps = sum(1 for d in dependencies if d.dep_type.value == "WAW")

        print(f"    RAW (Read After Write): {raw_deps}")
        print(f"    WAR (Write After Read): {war_deps}")
        print(f"    WAW (Write After Write): {waw_deps}")

        if dependencies:
            print("\n  Example dependencies:")
            for dep in dependencies[:5]:
                print(f"    {dep}")


def detect_invariants(binary: Binary):
    """Demonstrate invariant detection."""
    print("\n" + "=" * 60)
    print("INVARIANT DETECTION")
    print("=" * 60)

    detector = InvariantDetector(binary)
    functions = binary.get_functions()[:5]

    for func in functions:
        addr = func.get("offset", 0)
        name = func.get("name", f"func_{addr:x}")

        print(f"\nDetecting invariants in: {name} @ 0x{addr:x}")

        invariants = detector.detect_all_invariants(addr)

        print(f"  Invariants detected: {len(invariants)}")

        by_type = {}
        for inv in invariants:
            inv_type = inv.invariant_type.value
            if inv_type not in by_type:
                by_type[inv_type] = []
            by_type[inv_type].append(inv)

        for inv_type, invs in by_type.items():
            print(f"    {inv_type}: {len(invs)}")
            for inv in invs[:2]:
                print(f"      - {inv.description}")


def validate_semantics(binary: Binary):
    """Demonstrate semantic validation."""
    print("\n" + "=" * 60)
    print("SEMANTIC VALIDATION")
    print("=" * 60)

    validator = SemanticValidator(binary)
    detector = InvariantDetector(binary)

    functions = binary.get_functions()[:3]

    print("\nCapturing original invariants...")
    original_invariants = {}

    for func in functions:
        addr = func.get("offset", 0)
        invariants = detector.detect_all_invariants(addr)
        original_invariants[addr] = invariants
        print(f"  Function @ 0x{addr:x}: {len(invariants)} invariants")

    print("\nValidating mutations (simulated)...")
    print("Note: Validation performed after mutations are applied")

    for addr in list(original_invariants.keys())[:1]:
        name = next((f.get("name") for f in functions if f.get("offset") == addr), f"func_{addr:x}")

        print(f"\nValidating: {name} @ 0x{addr:x}")

        result = validator.validate_mutation(addr, original_invariants[addr])

        print(f"  Valid: {result['valid']}")
        print(f"  Violations: {result['violation_count']}")

        if result["violations"]:
            print("\n  Detected violations:")
            for violation in result["violations"][:3]:
                print(f"    - {violation.description}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python advanced_analysis.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]

    print("=" * 60)
    print("r2morph - Advanced Analysis Example")
    print("=" * 60)
    print(f"\nAnalyzing binary: {binary_path}\n")

    with Binary(binary_path) as binary:
        print("[+] Running analysis...")
        binary.analyze(level="aaa")

        arch_info = binary.get_arch_info()
        functions = binary.get_functions()

        print("\nBinary Information:")
        print(f"  Architecture: {arch_info['arch']} ({arch_info['bits']}-bit)")
        print(f"  Format: {arch_info['format']}")
        print(f"  Functions: {len(functions)}")

        analyze_control_flow(binary)
        analyze_dependencies(binary)
        detect_invariants(binary)
        validate_semantics(binary)

    print("\n" + "=" * 60)
    print("[+] Advanced analysis complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
