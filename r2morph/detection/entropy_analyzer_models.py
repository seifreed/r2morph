"""Result model for entropy analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EntropyResult:
    """Entropy analysis result."""

    overall_entropy: float
    section_entropies: dict[str, float]
    suspicious_sections: list[str]
    is_packed: bool
    analysis: str

    def __str__(self) -> str:
        status = "🔴 Likely packed/encrypted" if self.is_packed else "✅ Normal"
        return (
            f"Entropy Analysis:\n"
            f"  Overall: {self.overall_entropy:.4f}\n"
            f"  Status: {status}\n"
            f"  Suspicious sections: {len(self.suspicious_sections)}"
        )
