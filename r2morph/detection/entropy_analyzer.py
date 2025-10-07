"""
Entropy analysis for detecting suspicious patterns.
"""

import logging
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


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


class EntropyAnalyzer:
    """
    Analyzes entropy to detect packed/encrypted binaries.

    High entropy (>7.0) often indicates compression or encryption.
    """

    HIGH_ENTROPY_THRESHOLD = 7.0
    SUSPICIOUS_ENTROPY_THRESHOLD = 6.5

    def __init__(self):
        """Initialize entropy analyzer."""
        pass

    def analyze_file(self, path: Path) -> EntropyResult:
        """
        Analyze entropy of entire file.

        Args:
            path: File path

        Returns:
            EntropyResult
        """
        logger.info(f"Analyzing entropy of {path.name}")

        overall = self._calculate_file_entropy(path)

        section_entropies = self._analyze_sections(path)

        suspicious = [
            name
            for name, entropy in section_entropies.items()
            if entropy > self.SUSPICIOUS_ENTROPY_THRESHOLD
        ]

        is_packed = overall > self.HIGH_ENTROPY_THRESHOLD

        if is_packed:
            analysis = (
                f"High entropy ({overall:.2f}) suggests packing or encryption. "
                f"Mutations may not be effective on packed binaries."
            )
        elif overall > self.SUSPICIOUS_ENTROPY_THRESHOLD:
            analysis = f"Moderately high entropy ({overall:.2f}). Some sections may be compressed."
        else:
            analysis = f"Normal entropy ({overall:.2f}). Good candidate for mutations."

        return EntropyResult(
            overall_entropy=overall,
            section_entropies=section_entropies,
            suspicious_sections=suspicious,
            is_packed=is_packed,
            analysis=analysis,
        )

    def _calculate_file_entropy(self, path: Path) -> float:
        """
        Calculate Shannon entropy of entire file.

        Args:
            path: File path

        Returns:
            Entropy value (0-8)
        """
        with open(path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in counter.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def _analyze_sections(self, path: Path) -> dict[str, float]:
        """
        Analyze entropy of individual sections.

        Args:
            path: Binary path

        Returns:
            Dict of section -> entropy
        """
        from r2morph.core.binary import Binary

        section_entropies = {}

        try:
            with Binary(path) as binary:
                binary.analyze()
                sections = binary.get_sections()

                for section in sections:
                    name = section.get("name", "unknown")
                    vaddr = section.get("vaddr", 0)
                    size = section.get("vsize", 0)

                    if size == 0:
                        continue

                    try:
                        data_hex = binary.r2.cmd(f"p8 {size} @ 0x{vaddr:x}")
                        data = bytes.fromhex(data_hex.strip())

                        entropy = self._calculate_entropy(data)
                        section_entropies[name] = entropy

                    except Exception as e:
                        logger.debug(f"Could not analyze section {name}: {e}")

        except Exception as e:
            logger.error(f"Failed to analyze sections: {e}")

        return section_entropies

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate entropy of byte data.

        Args:
            data: Byte data

        Returns:
            Entropy value
        """
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in counter.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def compare_entropy(
        self, original_path: Path, morphed_path: Path
    ) -> tuple[float, float, float]:
        """
        Compare entropy between original and morphed binary.

        Args:
            original_path: Original binary
            morphed_path: Morphed binary

        Returns:
            Tuple of (original_entropy, morphed_entropy, delta)
        """
        orig_entropy = self._calculate_file_entropy(original_path)
        morph_entropy = self._calculate_file_entropy(morphed_path)
        delta = morph_entropy - orig_entropy

        logger.info(
            f"Entropy comparison: {orig_entropy:.4f} -> {morph_entropy:.4f} (delta: {delta:+.4f})"
        )

        return orig_entropy, morph_entropy, delta

    def visualize_entropy(self, path: Path, block_size: int = 256) -> list[float]:
        """
        Calculate entropy for blocks of the file (for visualization).

        Args:
            path: File path
            block_size: Size of each block

        Returns:
            List of entropy values per block
        """
        with open(path, "rb") as f:
            data = f.read()

        entropies = []

        for i in range(0, len(data), block_size):
            block = data[i : i + block_size]
            if block:
                entropy = self._calculate_entropy(block)
                entropies.append(entropy)

        return entropies
