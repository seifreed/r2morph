"""
Detection analysis module for evaluating mutation effectiveness.
"""

from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult
from r2morph.detection.evasion_scorer import EvasionScore, EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from r2morph.detection.packer_signatures import (
    PackerSignatureDatabase,
    PackerSignature,
    PackerType,
)
from r2morph.detection.control_flow_detector import (
    ControlFlowAnalyzer,
    ControlFlowAnalysisResult,
)
from r2morph.detection.pattern_matcher import (
    PatternMatcher,
    PatternMatchResult,
)
from r2morph.detection.obfuscation_detector import (
    ObfuscationDetector,
    ObfuscationAnalysisResult,
    ObfuscationType,
)
from r2morph.detection.anti_analysis_bypass import (
    AntiAnalysisBypass,
    AntiAnalysisType,
    BypassTechnique,
    BypassResult,
)

__all__ = [
    # Entropy analysis
    "EntropyAnalyzer",
    "EntropyResult",
    # Evasion scoring
    "EvasionScorer",
    "EvasionScore",
    # Similarity hashing
    "SimilarityHasher",
    # Packer signatures
    "PackerSignatureDatabase",
    "PackerSignature",
    "PackerType",
    # Control flow analysis
    "ControlFlowAnalyzer",
    "ControlFlowAnalysisResult",
    # Pattern matching
    "PatternMatcher",
    "PatternMatchResult",
    # Obfuscation detection (facade)
    "ObfuscationDetector",
    "ObfuscationAnalysisResult",
    "ObfuscationType",
    # Anti-analysis bypass
    "AntiAnalysisBypass",
    "AntiAnalysisType",
    "BypassTechnique",
    "BypassResult",
]
