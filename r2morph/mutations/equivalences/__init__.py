"""
Equivalence rules for instruction substitution.

This package contains architecture-specific equivalence rules in YAML format
and a loader to parse and expand them into usable equivalence groups.
"""

from r2morph.mutations.equivalences.loader import load_equivalence_rules

__all__ = ["load_equivalence_rules"]
