"""Contract tests for anti-analysis bypass model exports."""

from r2morph.detection import AntiAnalysisType as PublicAntiAnalysisType
from r2morph.detection import BypassResult as PublicBypassResult
from r2morph.detection import BypassTechnique as PublicBypassTechnique
from r2morph.detection.anti_analysis_bypass import AntiAnalysisBypass
from r2morph.detection.anti_analysis_bypass_models import (
    AntiAnalysisType as ModelsAntiAnalysisType,
)
from r2morph.detection.anti_analysis_bypass_models import BypassResult as ModelsBypassResult
from r2morph.detection.anti_analysis_bypass_models import (
    BypassTechnique as ModelsBypassTechnique,
)
from tests.utils.assertions import expect


def test_anti_analysis_bypass_models_are_reexported_from_detection_package():
    expect(not (PublicAntiAnalysisType is not ModelsAntiAnalysisType))
    expect(not (PublicBypassTechnique is not ModelsBypassTechnique))
    expect(not (PublicBypassResult is not ModelsBypassResult))
    expect(AntiAnalysisBypass is not None)
