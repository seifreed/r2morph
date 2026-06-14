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


def test_anti_analysis_bypass_models_are_reexported_from_detection_package():
    assert PublicAntiAnalysisType is ModelsAntiAnalysisType
    assert PublicBypassTechnique is ModelsBypassTechnique
    assert PublicBypassResult is ModelsBypassResult
    assert AntiAnalysisBypass is not None
