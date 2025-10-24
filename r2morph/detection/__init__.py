"""
Detection analysis module for evaluating mutation effectiveness.
"""

from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.evasion_scorer import EvasionScore, EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from r2morph.detection.obfuscation_detector import (
    ObfuscationDetector,
    ObfuscationAnalysisResult,
    PackerType,
    ObfuscationType
)
from r2morph.detection.anti_analysis_bypass import (
    AntiAnalysisBypass,
    AntiAnalysisType,
    BypassTechnique,
    BypassResult
)

__all__ = [
    "EvasionScorer",
    "EvasionScore",
    "SimilarityHasher",
    "EntropyAnalyzer",
    "ObfuscationDetector",
    "ObfuscationAnalysisResult",
    "PackerType",
    "ObfuscationType",
    "AntiAnalysisBypass",
    "AntiAnalysisType",
    "BypassTechnique",
    "BypassResult",
]
