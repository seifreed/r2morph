"""
Similarity hashing for comparing binaries (fuzzy hashing).
"""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class SimilarityHasher:
    """
    Generates similarity hashes (ssdeep, TLSH) for fuzzy comparison.

    These hashes allow comparing how similar two files are,
    even if they're not identical.
    """

    def __init__(self):
        """Initialize similarity hasher."""
        self.has_ssdeep = self._check_tool("ssdeep")
        self.has_tlsh = self._check_tool("tlsh")

        if not self.has_ssdeep and not self.has_tlsh:
            logger.warning("Neither ssdeep nor tlsh available - limited functionality")

    def _check_tool(self, tool: str) -> bool:
        """
        Check if a tool is available.

        Args:
            tool: Tool name

        Returns:
            True if available
        """
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=5)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def hash_file(self, path: Path) -> dict[str, str | None]:
        """
        Generate similarity hashes for a file.

        Args:
            path: File path

        Returns:
            Dict with ssdeep and tlsh hashes
        """
        result = {
            "ssdeep": None,
            "tlsh": None,
        }

        if self.has_ssdeep:
            result["ssdeep"] = self._ssdeep_hash(path)

        if self.has_tlsh:
            result["tlsh"] = self._tlsh_hash(path)

        return result

    def _ssdeep_hash(self, path: Path) -> str | None:
        """
        Generate ssdeep hash.

        Args:
            path: File path

        Returns:
            ssdeep hash or None
        """
        try:
            result = subprocess.run(
                ["ssdeep", "-b", str(path)], capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                output = result.stdout.strip()
                if "," in output:
                    return output.split(",")[0]

        except subprocess.SubprocessError as e:
            logger.error(f"ssdeep failed: {e}")

        return None

    def _tlsh_hash(self, path: Path) -> str | None:
        """
        Generate TLSH hash.

        Args:
            path: File path

        Returns:
            TLSH hash or None
        """
        try:
            result = subprocess.run(
                ["tlsh", "-f", str(path)], capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                output = result.stdout.strip()
                if output:
                    return output

        except subprocess.SubprocessError as e:
            logger.error(f"tlsh failed: {e}")

        return None

    def compare_ssdeep(self, hash1: str, hash2: str) -> int | None:
        """
        Compare two ssdeep hashes.

        Args:
            hash1: First hash
            hash2: Second hash

        Returns:
            Similarity score 0-100, or None
        """
        try:
            result = subprocess.run(
                ["ssdeep", "-a", "-s", hash1, hash2], capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.strip()
                import re

                match = re.search(r"(\d+)", output)
                if match:
                    return int(match.group(1))

        except subprocess.SubprocessError as e:
            logger.error(f"ssdeep comparison failed: {e}")

        return None

    def compare_files(self, path1: Path, path2: Path) -> dict[str, int | None]:
        """
        Compare similarity of two files.

        Args:
            path1: First file
            path2: Second file

        Returns:
            Dict with similarity scores
        """
        logger.info(f"Comparing {path1.name} vs {path2.name}")

        result = {
            "ssdeep_similarity": None,
            "tlsh_distance": None,
        }

        if self.has_ssdeep:
            hash1 = self._ssdeep_hash(path1)
            hash2 = self._ssdeep_hash(path2)

            if hash1 and hash2:
                result["ssdeep_similarity"] = self.compare_ssdeep(hash1, hash2)

        result["byte_similarity"] = self._byte_similarity(path1, path2)

        return result

    def _byte_similarity(self, path1: Path, path2: Path) -> float:
        """
        Calculate simple byte-level similarity.

        Args:
            path1: First file
            path2: Second file

        Returns:
            Similarity percentage 0-100
        """
        with open(path1, "rb") as f1, open(path2, "rb") as f2:
            data1 = f1.read()
            data2 = f2.read()

        if len(data1) != len(data2):
            return 0.0

        matches = sum(1 for a, b in zip(data1, data2, strict=False) if a == b)
        total = len(data1)

        return (matches / total * 100) if total > 0 else 0.0
