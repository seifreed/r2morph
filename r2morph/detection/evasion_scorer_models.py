"""Result model for evasion scoring."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EvasionScore:
    """Evasion effectiveness score."""

    overall_score: float
    hash_change_score: float
    entropy_score: float
    structure_score: float
    signature_score: float
    details: dict[str, float]

    def __str__(self) -> str:
        return (
            f"Evasion Score: {self.overall_score:.1f}/100\n"
            f"  Hash Change: {self.hash_change_score:.1f}/100\n"
            f"  Entropy: {self.entropy_score:.1f}/100\n"
            f"  Structure: {self.structure_score:.1f}/100\n"
            f"  Signature: {self.signature_score:.1f}/100"
        )
