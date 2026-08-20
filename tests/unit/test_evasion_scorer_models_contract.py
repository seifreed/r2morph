"""Contract tests for evasion scorer result models."""

from r2morph.detection import EvasionScore as PublicEvasionScore
from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.evasion_scorer_models import EvasionScore as ModelsEvasionScore
from tests.utils.assertions import expect


def test_evasion_score_is_reexported_from_detection_package():
    expect(not (PublicEvasionScore is not ModelsEvasionScore))
    expect(EvasionScorer is not None)
