"""Shellcode-equivalence checker extracted from SymbolicValidator (slice 2a).

Coordinates observable and transition checks using split collaborators.
Imported lazily by SymbolicValidator.__init__ (composition root).
"""

from __future__ import annotations

from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.shellcode_observables import compare_instruction_substitution_observables
from r2morph.validation.shellcode_transition import compare_instruction_substitution_transition


class ShellcodeEquivalenceChecker:
    """Bounded angr-shellcode observable/transition equivalence checks."""

    def _compare_instruction_substitution_observables(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare a small set of observable register/flag effects for InstructionSubstitution snippets."""
        return compare_instruction_substitution_observables(binary, pass_result, bridge_module)

    def _compare_instruction_substitution_transition(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare successor address and stack delta for supported substitution snippets."""
        return compare_instruction_substitution_transition(binary, pass_result, bridge_module)
