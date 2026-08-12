"""
Detection analysis module for evaluating mutation effectiveness.
"""

from r2morph.detection.anti_analysis_bypass import (
    AntiAnalysisBypass,
)
from r2morph.detection.anti_analysis_bypass_models import (
    AntiAnalysisType,
    BypassResult,
    BypassTechnique,
)
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer
from r2morph.detection.control_flow_detector_models import ControlFlowAnalysisResult
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.entropy_analyzer_models import EntropyResult
from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.evasion_scorer_models import EvasionScore
from r2morph.detection.obfuscation_detector import (
    ObfuscationDetector,
)
from r2morph.detection.obfuscation_detector_models import (
    ObfuscationAnalysisResult,
    ObfuscationType,
)
from r2morph.detection.packer_signature_models import PackerSignature, PackerType
from r2morph.detection.packer_signatures import PackerSignatureDatabase
from r2morph.detection.pattern_matcher import (
    PatternMatcher,
)
from r2morph.detection.pattern_matcher_models import PatternMatchResult
from r2morph.detection.similarity_hasher import SimilarityHasher

__all__ = [
    # Anti-analysis bypass
    "AntiAnalysisBypass",
    "AntiAnalysisType",
    "BypassResult",
    "BypassTechnique",
    "ControlFlowAnalysisResult",
    # Control flow analysis
    "ControlFlowAnalyzer",
    # Entropy analysis
    "EntropyAnalyzer",
    "EntropyResult",
    "EvasionScore",
    # Evasion scoring
    "EvasionScorer",
    "ObfuscationAnalysisResult",
    # Obfuscation detection (facade)
    "ObfuscationDetector",
    "ObfuscationType",
    "PackerSignature",
    # Packer signatures
    "PackerSignatureDatabase",
    "PackerType",
    "PatternMatchResult",
    # Pattern matching
    "PatternMatcher",
    # Similarity hashing
    "SimilarityHasher",
]
