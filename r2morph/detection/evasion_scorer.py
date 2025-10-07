"""
Score how effective mutations are at evading detection.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


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


class EvasionScorer:
    """
    Evaluates how effective mutations are at evading detection.

    Analyzes multiple aspects:
    - File hash change
    - Entropy preservation/change
    - Structural changes
    - Known signature patterns
    """

    def __init__(self):
        """Initialize evasion scorer."""
        self.weights = {
            "hash_change": 0.25,
            "entropy": 0.20,
            "structure": 0.30,
            "signature": 0.25,
        }

    def score(self, original_path: Path, morphed_path: Path) -> EvasionScore:
        """
        Calculate evasion score for morphed binary.

        Args:
            original_path: Original binary
            morphed_path: Morphed binary

        Returns:
            EvasionScore
        """
        logger.info("Calculating evasion score")

        hash_score = self._score_hash_change(original_path, morphed_path)
        entropy_score = self._score_entropy(original_path, morphed_path)
        structure_score = self._score_structure(original_path, morphed_path)
        signature_score = self._score_signatures(original_path, morphed_path)

        overall = (
            hash_score * self.weights["hash_change"]
            + entropy_score * self.weights["entropy"]
            + structure_score * self.weights["structure"]
            + signature_score * self.weights["signature"]
        )

        return EvasionScore(
            overall_score=overall,
            hash_change_score=hash_score,
            entropy_score=entropy_score,
            structure_score=structure_score,
            signature_score=signature_score,
            details={
                "hash_changed": hash_score == 100.0,
                "entropy_similar": entropy_score > 70.0,
                "structure_changed": structure_score > 50.0,
            },
        )

    def _score_hash_change(self, original_path: Path, morphed_path: Path) -> float:
        """
        Score based on hash change.

        Args:
            original_path: Original binary
            morphed_path: Morphed binary

        Returns:
            Score 0-100
        """
        import hashlib

        def hash_file(path: Path) -> str:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                sha256.update(f.read())
            return sha256.hexdigest()

        orig_hash = hash_file(original_path)
        morph_hash = hash_file(morphed_path)

        if orig_hash != morph_hash:
            return 100.0

        return 0.0

    def _score_entropy(self, original_path: Path, morphed_path: Path) -> float:
        """
        Score based on entropy preservation.

        Good mutations preserve entropy (look natural).

        Args:
            original_path: Original binary
            morphed_path: Morphed binary

        Returns:
            Score 0-100
        """
        import math
        from collections import Counter

        def calc_entropy(path: Path) -> float:
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

        orig_entropy = calc_entropy(original_path)
        morph_entropy = calc_entropy(morphed_path)

        diff = abs(orig_entropy - morph_entropy)

        score = max(0, 100 - (diff * 50))

        return score

    def _score_structure(self, original_path: Path, morphed_path: Path) -> float:
        """
        Score based on structural changes.

        More structural changes = better evasion.

        Args:
            original_path: Original binary
            morphed_path: Morphed binary

        Returns:
            Score 0-100
        """
        from r2morph.core.binary import Binary

        try:
            with Binary(original_path) as orig, Binary(morphed_path) as morph:
                orig.analyze()
                morph.analyze()

                orig_funcs = orig.get_functions()
                morph_funcs = morph.get_functions()

                changed = 0
                total = len(orig_funcs)

                orig_func_map = {f["offset"]: f for f in orig_funcs}
                morph_func_map = {f["offset"]: f for f in morph_funcs}

                for addr in orig_func_map:
                    if addr in morph_func_map:
                        orig_size = orig_func_map[addr].get("size", 0)
                        morph_size = morph_func_map[addr].get("size", 0)

                        if orig_size != morph_size:
                            changed += 1

                if total > 0:
                    return (changed / total) * 100
                else:
                    return 0.0

        except Exception as e:
            logger.error(f"Error scoring structure: {e}")
            return 0.0

    def _score_signatures(self, original_path: Path, morphed_path: Path) -> float:
        """
        Score based on signature pattern changes.

        Checks if common byte patterns have changed.

        Args:
            original_path: Original binary
            morphed_path: Morphed binary

        Returns:
            Score 0-100
        """

        def extract_ngrams(path: Path, n: int = 4) -> set:
            with open(path, "rb") as f:
                data = f.read()

            ngrams = set()
            for i in range(len(data) - n + 1):
                ngram = data[i : i + n]
                ngrams.add(ngram)

            return ngrams

        orig_ngrams = extract_ngrams(original_path, n=8)
        morph_ngrams = extract_ngrams(morphed_path, n=8)

        intersection = orig_ngrams & morph_ngrams
        union = orig_ngrams | morph_ngrams

        if len(union) == 0:
            return 0.0

        similarity = len(intersection) / len(union)

        score = (1.0 - similarity) * 100

        return score

    def recommend_improvements(self, score: EvasionScore) -> list[str]:
        """
        Recommend improvements based on score.

        Args:
            score: Current evasion score

        Returns:
            List of recommendations
        """
        recommendations = []

        if score.hash_change_score < 100:
            recommendations.append("⚠️ Hash didn't change - ensure mutations are applied")

        if score.entropy_score < 50:
            recommendations.append("⚠️ Entropy changed significantly - may look suspicious")

        if score.structure_score < 30:
            recommendations.append("💡 Consider more aggressive mutations to change structure")

        if score.signature_score < 40:
            recommendations.append(
                "💡 Byte patterns too similar - add more instruction substitutions"
            )

        if score.overall_score > 80:
            recommendations.append("✅ Excellent evasion score!")
        elif score.overall_score > 60:
            recommendations.append("👍 Good evasion score")
        elif score.overall_score > 40:
            recommendations.append("⚠️ Moderate evasion - consider more mutations")
        else:
            recommendations.append("🔴 Low evasion score - mutations may be ineffective")

        return recommendations
