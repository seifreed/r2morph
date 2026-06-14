"""Contract tests for pattern matcher result models."""

from r2morph.detection import PatternMatchResult as PublicPatternMatchResult
from r2morph.detection.pattern_matcher import PatternMatchResult
from r2morph.detection.pattern_matcher_models import PatternMatchResult as ModelsPatternMatchResult


def test_pattern_match_result_is_reexported_from_detection_package():
    assert PublicPatternMatchResult is ModelsPatternMatchResult is PatternMatchResult
