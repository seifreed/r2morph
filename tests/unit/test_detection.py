"""
Unit tests for detection modules.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from r2morph.detection.control_flow_detector import (
    ControlFlowAnalyzer,
    ControlFlowAnalysisResult,
)
from r2morph.detection.obfuscation_detector import (
    ObfuscationDetector,
    ObfuscationAnalysisResult,
    ObfuscationType,
)
from r2morph.detection.packer_signatures import PackerSignatureDatabase, PackerType
from r2morph.detection.pattern_matcher import PatternMatcher, PatternMatchResult
from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult
from r2morph.detection.evasion_scorer import EvasionScorer, EvasionScore


class TestControlFlowAnalysisResult:
    def test_result_creation(self):
        result = ControlFlowAnalysisResult()
        assert result.cff_detected is False
        assert result.cff_confidence == 0.0
        assert result.opaque_predicates_count == 0

    def test_result_with_values(self):
        result = ControlFlowAnalysisResult(
            cff_detected=True,
            cff_confidence=0.8,
            opaque_predicates_count=5,
            mba_expressions_count=3,
        )
        assert result.cff_detected is True
        assert result.cff_confidence == 0.8
        assert result.opaque_predicates_count == 5
        assert result.mba_expressions_count == 3

    def test_result_vm_detection(self):
        result = ControlFlowAnalysisResult(
            vm_detected=True,
            vm_confidence=0.9,
            vm_handler_count=42,
            vm_indicators=["indirect_jumps", "dispatcher_pattern"],
        )
        assert result.vm_detected is True
        assert result.vm_handler_count == 42
        assert "indirect_jumps" in result.vm_indicators


class TestPackerType:
    def test_packer_types(self):
        assert PackerType.NONE.value == "none"
        assert PackerType.UPX.value == "upx"
        assert PackerType.VMPROTECT.value == "vmprotect"
        assert PackerType.THEMIDA.value == "themida"


class TestPackerSignatureDatabase:
    def test_database_initialization(self):
        db = PackerSignatureDatabase()
        assert db is not None
        assert hasattr(db, "signatures")


class TestPatternMatchResult:
    def test_result_creation(self):
        result = PatternMatchResult()
        assert result.anti_debug_detected is False
        assert result.anti_debug_confidence == 0.0
        assert result.anti_debug_apis == []

    def test_result_with_values(self):
        result = PatternMatchResult(
            anti_debug_detected=True,
            anti_debug_confidence=0.9,
            anti_debug_apis=["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
            anti_vm_detected=True,
            anti_vm_confidence=0.7,
            anti_vm_artifacts=["vmware", "virtualbox"],
        )
        assert result.anti_debug_detected is True
        assert result.anti_debug_confidence == 0.9
        assert "IsDebuggerPresent" in result.anti_debug_apis
        assert result.anti_vm_detected is True
        assert "vmware" in result.anti_vm_artifacts


class TestPatternMatcher:
    def test_matcher_initialization(self):
        binary = Mock()
        matcher = PatternMatcher(binary)
        assert matcher is not None

    def test_matcher_has_anti_debug_apis(self):
        binary = Mock()
        matcher = PatternMatcher(binary)
        assert hasattr(matcher, "ANTI_DEBUG_APIS")
        assert "IsDebuggerPresent" in matcher.ANTI_DEBUG_APIS

    def test_matcher_has_vm_artifacts(self):
        binary = Mock()
        matcher = PatternMatcher(binary)
        assert hasattr(matcher, "VM_ARTIFACTS")
        assert "vmware" in matcher.VM_ARTIFACTS


class TestEntropyAnalyzer:
    def test_analyzer_initialization(self):
        analyzer = EntropyAnalyzer()
        assert analyzer is not None

    def test_analyzer_has_methods(self):
        analyzer = EntropyAnalyzer()
        assert hasattr(analyzer, "analyze_file")
        assert hasattr(analyzer, "_calculate_entropy")


class TestEntropyResult:
    def test_result_creation(self):
        result = EntropyResult(
            overall_entropy=7.5,
            section_entropies={},
            suspicious_sections=[],
            is_packed=False,
            analysis="Test",
        )
        assert result.overall_entropy == 7.5

    def test_result_str(self):
        result = EntropyResult(
            overall_entropy=7.5,
            section_entropies={".text": 7.0, ".data": 2.0},
            suspicious_sections=[],
            is_packed=False,
            analysis="Normal entropy",
        )
        s = str(result)
        assert "7.5" in s or "7.50" in s


class TestEvasionScore:
    def test_score_creation(self):
        score = EvasionScore(
            overall_score=75.0,
            hash_change_score=100.0,
            entropy_score=80.0,
            structure_score=70.0,
            signature_score=60.0,
            details={},
        )
        assert score.overall_score == 75.0
        assert score.hash_change_score == 100.0

    def test_score_str(self):
        score = EvasionScore(
            overall_score=75.0,
            hash_change_score=100.0,
            entropy_score=80.0,
            structure_score=70.0,
            signature_score=60.0,
            details={},
        )
        s = str(score)
        assert "75" in s


class TestEvasionScorer:
    def test_scorer_initialization(self):
        scorer = EvasionScorer()
        assert scorer is not None

    def test_scorer_weights(self):
        scorer = EvasionScorer()
        assert "hash_change" in scorer.weights
        assert "entropy" in scorer.weights
        assert "structure" in scorer.weights
        assert "signature" in scorer.weights


class TestObfuscationType:
    def test_obfuscation_types(self):
        assert ObfuscationType.CONTROL_FLOW_FLATTENING.value == "cff"
        assert ObfuscationType.OPAQUE_PREDICATES.value == "opaque_predicates"
        assert ObfuscationType.VIRTUALIZATION.value == "virtualization"
        assert ObfuscationType.PACKING.value == "packing"


class TestObfuscationAnalysisResult:
    def test_result_creation(self):
        result = ObfuscationAnalysisResult()
        assert result.packer_detected == PackerType.NONE
        assert len(result.obfuscation_techniques) == 0

    def test_result_with_techniques(self):
        result = ObfuscationAnalysisResult(
            packer_detected=PackerType.UPX,
            obfuscation_techniques=[
                ObfuscationType.PACKING,
                ObfuscationType.CONTROL_FLOW_FLATTENING,
            ],
            confidence_score=0.85,
        )
        assert result.packer_detected == PackerType.UPX
        assert len(result.obfuscation_techniques) == 2
        assert result.confidence_score == 0.85


class TestObfuscationDetector:
    def test_detector_initialization(self):
        detector = ObfuscationDetector()
        assert detector is not None
        assert detector.packer_db is not None
        assert detector.entropy_analyzer is not None


class TestEntropyAnalysis:
    def test_entropy_constants(self):
        analyzer = EntropyAnalyzer()
        assert analyzer.HIGH_ENTROPY_THRESHOLD == 7.0
        assert analyzer.SUSPICIOUS_ENTROPY_THRESHOLD == 6.5

    def test_entropy_score_range(self):
        high_score = 100.0
        low_score = 0.0
        assert 0 <= high_score <= 100
        assert 0 <= low_score <= 100
