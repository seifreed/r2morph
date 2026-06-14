"""
Score how effective mutations are at evading detection.
"""

import logging
from pathlib import Path

from r2morph.detection.evasion_scorer_helpers import (
    DEFAULT_EVASION_WEIGHTS,
    compose_evasion_score,
    recommend_improvements,
)
from r2morph.detection.evasion_scorer_models import EvasionScore
from r2morph.utils.entropy import calculate_file_entropy
from r2morph.utils.hashing import hash_file

logger = logging.getLogger(__name__)


class EvasionScorer:
    """
    Evaluates how effective mutations are at evading detection.

    Analyzes multiple aspects:
    - File hash change
    - Entropy preservation/change
    - Structural changes
    - Known signature patterns
    """

    def __init__(self) -> None:
        """Initialize evasion scorer."""
        self.weights = dict(DEFAULT_EVASION_WEIGHTS)

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

        return compose_evasion_score(
            hash_score=hash_score,
            entropy_score=entropy_score,
            structure_score=structure_score,
            signature_score=signature_score,
            weights=self.weights,
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
        orig_entropy = calculate_file_entropy(original_path)
        morph_entropy = calculate_file_entropy(morphed_path)

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
        return recommend_improvements(score)
