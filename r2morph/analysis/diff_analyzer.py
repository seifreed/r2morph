"""
Differential analysis between original and morphed binaries.
"""

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


@dataclass
class DiffStats:
    """Statistics about binary differences."""

    total_bytes: int
    changed_bytes: int
    percent_changed: float
    hash_original: str
    hash_morphed: str
    entropy_original: float
    entropy_morphed: float
    entropy_delta: float
    functions_changed: int
    instructions_changed: int

    def __str__(self) -> str:
        return (
            f"Diff Statistics:\n"
            f"  Bytes changed: {self.changed_bytes}/{self.total_bytes} ({self.percent_changed:.2f}%)\n"
            f"  Hash (original): {self.hash_original[:16]}...\n"
            f"  Hash (morphed):  {self.hash_morphed[:16]}...\n"
            f"  Entropy delta: {self.entropy_delta:+.4f}\n"
            f"  Functions changed: {self.functions_changed}\n"
            f"  Instructions changed: {self.instructions_changed}"
        )


class DiffAnalyzer:
    """
    Analyzes differences between original and morphed binaries.

    Provides metrics like similarity score, entropy changes,
    and visual diff of changes.
    """

    def __init__(self):
        """Initialize diff analyzer."""
        self.original: Binary | None = None
        self.morphed: Binary | None = None
        self.diff_stats: DiffStats | None = None
        self._original_path: Path | None = None
        self._morphed_path: Path | None = None

    def compare(self, original_path: Path, morphed_path: Path) -> DiffStats:
        """
        Compare two binaries.

        Args:
            original_path: Path to original binary
            morphed_path: Path to morphed binary

        Returns:
            DiffStats with comparison details
        """
        logger.info(f"Comparing {original_path.name} vs {morphed_path.name}")

        self._original_path = Path(original_path)
        self._morphed_path = Path(morphed_path)

        with Binary(original_path) as orig, Binary(morphed_path) as morph:
            orig.analyze()
            morph.analyze()

            self.original = orig
            self.morphed = morph

            hash_orig, hash_morph = self._calculate_hashes(original_path, morphed_path)
            changed_bytes, total_bytes = self._count_changed_bytes(original_path, morphed_path)
            percent_changed = (changed_bytes / total_bytes * 100) if total_bytes > 0 else 0

            entropy_orig = self._calculate_entropy(original_path)
            entropy_morph = self._calculate_entropy(morphed_path)
            entropy_delta = entropy_morph - entropy_orig

            funcs_changed = self._count_changed_functions()
            insns_changed = self._count_changed_instructions()

            self.diff_stats = DiffStats(
                total_bytes=total_bytes,
                changed_bytes=changed_bytes,
                percent_changed=percent_changed,
                hash_original=hash_orig,
                hash_morphed=hash_morph,
                entropy_original=entropy_orig,
                entropy_morphed=entropy_morph,
                entropy_delta=entropy_delta,
                functions_changed=funcs_changed,
                instructions_changed=insns_changed,
            )

        logger.info(f"Comparison complete: {self.diff_stats}")
        return self.diff_stats

    def get_similarity_score(self) -> float:
        """
        Calculate similarity score (0-100%).

        Returns:
            Similarity percentage
        """
        if not self.diff_stats:
            return 0.0

        return 100.0 - self.diff_stats.percent_changed

    def visualize_changes(self, output_file: Path | None = None) -> str:
        """
        Create a visual representation of changes.

        Args:
            output_file: Optional file to save visualization

        Returns:
            Visualization string
        """
        if not self.diff_stats:
            return "No comparison data available"

        viz = []
        viz.append("=" * 60)
        viz.append("BINARY DIFF VISUALIZATION")
        viz.append("=" * 60)
        viz.append("")
        viz.append(str(self.diff_stats))
        viz.append("")

        viz.append("Function Changes:")
        viz.append("-" * 60)

        # Reopen binaries if needed
        if self._original_path and self._morphed_path:
            with Binary(self._original_path) as orig, Binary(self._morphed_path) as morph:
                orig.analyze()
                morph.analyze()
                orig_funcs = {f.get("offset", f.get("addr", 0)): f for f in orig.get_functions()}
                morph_funcs = {f.get("offset", f.get("addr", 0)): f for f in morph.get_functions()}

                for addr in orig_funcs:
                    if addr in morph_funcs:
                        orig_size = orig_funcs[addr].get("size", 0)
                        morph_size = morph_funcs[addr].get("size", 0)

                        if orig_size != morph_size:
                            func_name = orig_funcs[addr].get("name", f"0x{addr:x}")
                            viz.append(
                                f"  {func_name}: "
                                f"{orig_size} bytes -> {morph_size} bytes "
                                f"({morph_size - orig_size:+d})"
                            )

        viz.append("")

        similarity = self.get_similarity_score()
        bar_length = 40
        filled = int(similarity / 100 * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)

        viz.append(f"Similarity: [{bar}] {similarity:.1f}%")
        viz.append("")

        result = "\n".join(viz)

        if output_file:
            output_file.write_text(result)
            logger.info(f"Saved visualization to {output_file}")

        return result

    def _calculate_hashes(self, path1: Path, path2: Path) -> tuple[str, str]:
        """
        Calculate SHA256 hashes of both files.

        Args:
            path1: First file
            path2: Second file

        Returns:
            Tuple of (hash1, hash2)
        """

        def hash_file(path: Path) -> str:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()

        return hash_file(path1), hash_file(path2)

    def _count_changed_bytes(self, path1: Path, path2: Path) -> tuple[int, int]:
        """
        Count how many bytes differ between files.

        Args:
            path1: First file
            path2: Second file

        Returns:
            Tuple of (changed_bytes, total_bytes)
        """
        with open(path1, "rb") as f1, open(path2, "rb") as f2:
            data1 = f1.read()
            data2 = f2.read()

        total = max(len(data1), len(data2))
        changed = 0

        for i in range(min(len(data1), len(data2))):
            if data1[i] != data2[i]:
                changed += 1

        changed += abs(len(data1) - len(data2))

        return changed, total

    def _calculate_entropy(self, path: Path) -> float:
        """
        Calculate Shannon entropy of file.

        Args:
            path: File path

        Returns:
            Entropy value (0-8)
        """
        import math
        from collections import Counter

        with open(path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in counter.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return entropy

    def _count_changed_functions(self) -> int:
        """
        Count number of functions that changed.

        Returns:
            Number of changed functions
        """
        if not self.original or not self.morphed:
            return 0

        orig_funcs = {f.get("offset", f.get("addr", 0)): f for f in self.original.get_functions()}
        morph_funcs = {f.get("offset", f.get("addr", 0)): f for f in self.morphed.get_functions()}

        changed = 0

        for addr in orig_funcs:
            if addr in morph_funcs:
                if orig_funcs[addr].get("size") != morph_funcs[addr].get("size"):
                    changed += 1

        return changed

    def _count_changed_instructions(self) -> int:
        """
        Count number of instructions that changed.

        Returns:
            Number of changed instructions
        """
        if not self.diff_stats:
            return 0

        return self.diff_stats.changed_bytes // 3

    def generate_report(self, output_file: Path):
        """
        Generate a detailed diff report.

        Args:
            output_file: Output file path
        """
        if not self.diff_stats:
            logger.warning("No comparison data available for report")
            return

        report = []
        report.append("# Binary Diff Analysis Report\n")
        report.append(f"Generated: {__import__('datetime').datetime.now()}\n")
        report.append("\n## Summary\n")
        report.append(f"```\n{self.diff_stats}\n```\n")

        report.append("\n## Metrics\n")
        report.append(f"- **Similarity Score**: {self.get_similarity_score():.2f}%\n")
        report.append(f"- **Bytes Changed**: {self.diff_stats.changed_bytes:,}\n")
        report.append(f"- **Entropy Change**: {self.diff_stats.entropy_delta:+.4f}\n")

        report.append("\n## Hashes\n")
        report.append(f"- **Original**: `{self.diff_stats.hash_original}`\n")
        report.append(f"- **Morphed**:  `{self.diff_stats.hash_morphed}`\n")

        report.append("\n## Visualization\n")
        report.append("```\n")
        report.append(self.visualize_changes())
        report.append("\n```\n")

        output_file.write_text("".join(report))
        logger.info(f"Generated report: {output_file}")
