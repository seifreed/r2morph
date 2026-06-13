"""Shared data models for hardened mutation passes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from r2morph.mutations.cfg_aware import CFGAwareMutationResult


@dataclass
class HardenedMutationResult(CFGAwareMutationResult):
    """Result of a hardened mutation with pattern preservation."""

    patterns_preserved: int = 0
    patterns_avoided: int = 0
    integrity_violations: int = 0
    preservation_report: dict[str, Any] = field(default_factory=dict)
    integrity_report: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "patterns_preserved": self.patterns_preserved,
                "patterns_avoided": self.patterns_avoided,
                "integrity_violations": self.integrity_violations,
                "preservation_report": self.preservation_report,
                "integrity_report": self.integrity_report,
            }
        )
        return base


__all__ = ["HardenedMutationResult"]
