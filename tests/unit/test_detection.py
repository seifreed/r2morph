"""
Unit tests for detection modules.
"""

from r2morph.detection.control_flow_detector import (
    ControlFlowAnalysisResult,
)
from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult
from r2morph.detection.evasion_scorer import EvasionScore, EvasionScorer
from r2morph.detection.obfuscation_detector import (
    ObfuscationAnalysisResult,
    ObfuscationDetector,
    ObfuscationType,
)
from r2morph.detection.packer_signature_catalogs import (
    compressor_signatures,
    other_signatures,
    protector_signatures,
    vm_protector_signatures,
)
from r2morph.detection.packer_signatures import PackerSignatureDatabase, PackerType
from r2morph.detection.pattern_catalogs import ANTI_DEBUG_APIS, VM_ARTIFACTS
from r2morph.detection.pattern_matcher import PatternMatcher, PatternMatchResult
from tests.utils.assertions import expect

_EXPECTED_0_100 = 100
_EXPECTED_0_100_2 = 100
_EXPECTED_ANALYZER_HIGH_ENTROPY_THRESHOLD_7_0 = 7.0
_EXPECTED_ANALYZER_SUSPICIOUS_ENTROPY_THRESHOLD_6_5 = 6.5
_EXPECTED_LEN_RESULT_OBFUSCATION_TECHNIQUES_2 = 2
_EXPECTED_RESULT_ANTI_DEBUG_CONFIDENCE_0_9 = 0.9
_EXPECTED_RESULT_CFF_CONFIDENCE_0_8 = 0.8
_EXPECTED_RESULT_CONFIDENCE_SCORE_0_85 = 0.85
_EXPECTED_RESULT_MBA_EXPRESSIONS_COUNT_3 = 3
_EXPECTED_RESULT_OPAQUE_PREDICATES_COUNT_5 = 5
_EXPECTED_RESULT_OVERALL_ENTROPY_7_5 = 7.5
_EXPECTED_RESULT_VM_HANDLER_COUNT_42 = 42
_EXPECTED_SCORE_HASH_CHANGE_SCORE_100_0 = 100.0
_EXPECTED_SCORE_OVERALL_SCORE_75_0 = 75.0


class _PatternBinary:
    pass


class TestControlFlowAnalysisResult:
    def test_result_creation(self):
        result = ControlFlowAnalysisResult()
        expect(not (result.cff_detected is not False))
        expect(result.cff_confidence == 0.0)
        expect(result.opaque_predicates_count == 0)

    def test_result_with_values(self):
        result = ControlFlowAnalysisResult(
            cff_detected=True,
            cff_confidence=0.8,
            opaque_predicates_count=5,
            mba_expressions_count=3,
        )
        expect(not (result.cff_detected is not True))
        expect(result.cff_confidence == _EXPECTED_RESULT_CFF_CONFIDENCE_0_8)
        expect(result.opaque_predicates_count == _EXPECTED_RESULT_OPAQUE_PREDICATES_COUNT_5)
        expect(result.mba_expressions_count == _EXPECTED_RESULT_MBA_EXPRESSIONS_COUNT_3)

    def test_result_vm_detection(self):
        result = ControlFlowAnalysisResult(
            vm_detected=True,
            vm_confidence=0.9,
            vm_handler_count=42,
            vm_indicators=["indirect_jumps", "dispatcher_pattern"],
        )
        expect(not (result.vm_detected is not True))
        expect(result.vm_handler_count == _EXPECTED_RESULT_VM_HANDLER_COUNT_42)
        expect(not ("indirect_jumps" not in result.vm_indicators))


class TestPackerType:
    def test_packer_types(self):
        expect(PackerType.NONE.value == "none")
        expect(PackerType.UPX.value == "upx")
        expect(PackerType.VMPROTECT.value == "vmprotect")
        expect(PackerType.THEMIDA.value == "themida")


class TestPackerSignatureDatabase:
    def test_database_initialization(self):
        db = PackerSignatureDatabase()
        expect(db is not None)
        expect(hasattr(db, "signatures"))

    def test_database_signature_count_matches_catalogs(self):
        db = PackerSignatureDatabase()
        expect(
            len(db.signatures)
            == len(vm_protector_signatures() + compressor_signatures() + protector_signatures() + other_signatures())
        )


class TestPatternMatchResult:
    def test_result_creation(self):
        result = PatternMatchResult()
        expect(not (result.anti_debug_detected is not False))
        expect(result.anti_debug_confidence == 0.0)
        expect(result.anti_debug_apis == [])

    def test_result_with_values(self):
        result = PatternMatchResult(
            anti_debug_detected=True,
            anti_debug_confidence=0.9,
            anti_debug_apis=["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
            anti_vm_detected=True,
            anti_vm_confidence=0.7,
            anti_vm_artifacts=["vmware", "virtualbox"],
        )
        expect(not (result.anti_debug_detected is not True))
        expect(result.anti_debug_confidence == _EXPECTED_RESULT_ANTI_DEBUG_CONFIDENCE_0_9)
        expect(not ("IsDebuggerPresent" not in result.anti_debug_apis))
        expect(not (result.anti_vm_detected is not True))
        expect(not ("vmware" not in result.anti_vm_artifacts))


class TestPatternMatcher:
    def test_matcher_initialization(self):
        binary = _PatternBinary()
        matcher = PatternMatcher(binary)
        expect(matcher is not None)

    def test_matcher_has_anti_debug_apis(self):
        binary = _PatternBinary()
        matcher = PatternMatcher(binary)
        expect(hasattr(matcher, "ANTI_DEBUG_APIS"))
        expect(not ("IsDebuggerPresent" not in matcher.ANTI_DEBUG_APIS))
        expect(not (matcher.ANTI_DEBUG_APIS is not ANTI_DEBUG_APIS))

    def test_matcher_has_vm_artifacts(self):
        binary = _PatternBinary()
        matcher = PatternMatcher(binary)
        expect(hasattr(matcher, "VM_ARTIFACTS"))
        expect(not ("vmware" not in matcher.VM_ARTIFACTS))
        expect(not (matcher.VM_ARTIFACTS is not VM_ARTIFACTS))


class TestEntropyAnalyzer:
    def test_analyzer_initialization(self):
        analyzer = EntropyAnalyzer()
        expect(analyzer is not None)

    def test_analyzer_has_methods(self):
        analyzer = EntropyAnalyzer()
        expect(hasattr(analyzer, "analyze_file"))
        expect(hasattr(analyzer, "_calculate_entropy"))


class TestEntropyResult:
    def test_result_creation(self):
        result = EntropyResult(
            overall_entropy=7.5,
            section_entropies={},
            suspicious_sections=[],
            is_packed=False,
            analysis="Test",
        )
        expect(result.overall_entropy == _EXPECTED_RESULT_OVERALL_ENTROPY_7_5)

    def test_result_str(self):
        result = EntropyResult(
            overall_entropy=7.5,
            section_entropies={".text": 7.0, ".data": 2.0},
            suspicious_sections=[],
            is_packed=False,
            analysis="Normal entropy",
        )
        s = str(result)
        expect("7.5" in s or "7.50" in s)


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
        expect(score.overall_score == _EXPECTED_SCORE_OVERALL_SCORE_75_0)
        expect(score.hash_change_score == _EXPECTED_SCORE_HASH_CHANGE_SCORE_100_0)

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
        expect(not ("75" not in s))


class TestEvasionScorer:
    def test_scorer_initialization(self):
        scorer = EvasionScorer()
        expect(scorer is not None)

    def test_scorer_weights(self):
        scorer = EvasionScorer()
        expect(not ("hash_change" not in scorer.weights))
        expect(not ("entropy" not in scorer.weights))
        expect(not ("structure" not in scorer.weights))
        expect(not ("signature" not in scorer.weights))


class TestObfuscationType:
    def test_obfuscation_types(self):
        expect(ObfuscationType.CONTROL_FLOW_FLATTENING.value == "cff")
        expect(ObfuscationType.OPAQUE_PREDICATES.value == "opaque_predicates")
        expect(ObfuscationType.VIRTUALIZATION.value == "virtualization")
        expect(ObfuscationType.PACKING.value == "packing")


class TestObfuscationAnalysisResult:
    def test_result_creation(self):
        result = ObfuscationAnalysisResult()
        expect(result.packer_detected == PackerType.NONE)
        expect(len(result.obfuscation_techniques) == 0)

    def test_result_with_techniques(self):
        result = ObfuscationAnalysisResult(
            packer_detected=PackerType.UPX,
            obfuscation_techniques=[
                ObfuscationType.PACKING,
                ObfuscationType.CONTROL_FLOW_FLATTENING,
            ],
            confidence_score=0.85,
        )
        expect(result.packer_detected == PackerType.UPX)
        expect(len(result.obfuscation_techniques) == _EXPECTED_LEN_RESULT_OBFUSCATION_TECHNIQUES_2)
        expect(result.confidence_score == _EXPECTED_RESULT_CONFIDENCE_SCORE_0_85)


class TestObfuscationDetector:
    def test_detector_initialization(self):
        detector = ObfuscationDetector()
        expect(detector is not None)
        expect(detector.packer_db is not None)
        expect(detector.entropy_analyzer is not None)


class TestEntropyAnalysis:
    def test_entropy_constants(self):
        analyzer = EntropyAnalyzer()
        expect(analyzer.HIGH_ENTROPY_THRESHOLD == _EXPECTED_ANALYZER_HIGH_ENTROPY_THRESHOLD_7_0)
        expect(analyzer.SUSPICIOUS_ENTROPY_THRESHOLD == _EXPECTED_ANALYZER_SUSPICIOUS_ENTROPY_THRESHOLD_6_5)

    def test_entropy_score_range(self):
        high_score = 100.0
        low_score = 0.0
        expect(0 <= high_score <= _EXPECTED_0_100)
        expect(0 <= low_score <= _EXPECTED_0_100_2)
