"""Contract tests for evasion scorer result models."""

from r2morph.detection import EvasionScore as PublicEvasionScore
from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.evasion_scorer_models import EvasionScore as ModelsEvasionScore


def test_evasion_score_is_reexported_from_detection_package():
    assert PublicEvasionScore is ModelsEvasionScore
    assert EvasionScorer is not None
