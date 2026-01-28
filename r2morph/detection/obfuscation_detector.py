"""
Enhanced obfuscation detector for identifying packer types and obfuscation techniques.

This module coordinates specialized analyzers to detect:
- VMProtect, Themida, and other commercial packers
- Control flow obfuscation patterns
- Mixed Boolean Arithmetic (MBA) expressions
- Virtual machine-based obfuscation
- Anti-analysis techniques
"""

import datetime
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.packer_signatures import PackerSignatureDatabase, PackerType
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer
from r2morph.detection.pattern_matcher import PatternMatcher

logger = logging.getLogger(__name__)


class ObfuscationType(Enum):
    """Types of obfuscation techniques."""

    CONTROL_FLOW_FLATTENING = "cff"
    OPAQUE_PREDICATES = "opaque_predicates"
    MIXED_BOOLEAN_ARITHMETIC = "mba"
    INSTRUCTION_SUBSTITUTION = "inst_substitution"
    VIRTUALIZATION = "virtualization"
    PACKING = "packing"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    STRING_ENCRYPTION = "string_encryption"
    IMPORT_HIDING = "import_hiding"


@dataclass
class ObfuscationAnalysisResult:
    """Result of obfuscation analysis."""

    packer_detected: PackerType = PackerType.NONE
    obfuscation_techniques: list[ObfuscationType] = field(default_factory=list)
    confidence_scores: dict[str, float] = field(default_factory=dict)
    vm_detected: bool = False
    vm_handler_count: int = 0
    mba_expressions_found: int = 0
    opaque_predicates_found: int = 0
    anti_analysis_detected: bool = False
    control_flow_flattened: bool = False
    mba_detected: bool = False
    confidence_score: float = 0.0
    analysis_details: dict[str, Any] = field(default_factory=dict)
    requires_devirtualization: bool = False
    requires_dynamic_analysis: bool = False


class ObfuscationDetector:
    """
    Coordinates obfuscation detection using specialized analyzers.

    This is a facade class that orchestrates packer signature matching,
    control flow analysis, pattern matching, and entropy analysis to
    provide comprehensive obfuscation detection.
    """

    def __init__(self):
        """Initialize obfuscation detector with specialized analyzers."""
        self.packer_db = PackerSignatureDatabase()
        self.entropy_analyzer = EntropyAnalyzer()

    def analyze_binary(self, binary: Binary) -> ObfuscationAnalysisResult:
        """
        Perform comprehensive obfuscation analysis.

        Args:
            binary: Binary to analyze

        Returns:
            Complete obfuscation analysis result
        """
        logger.info("Starting comprehensive obfuscation analysis")

        result = ObfuscationAnalysisResult()

        # Ensure binary is analyzed
        if not binary.is_analyzed():
            binary.analyze()

        # Create specialized analyzers for this binary
        cf_analyzer = ControlFlowAnalyzer(binary)
        pattern_matcher = PatternMatcher(binary)

        # 1. Packer detection
        result.packer_detected = self.packer_db.detect(binary, self.entropy_analyzer)

        # 2. Entropy analysis
        entropy_result = self.entropy_analyzer.analyze_file(Path(binary.path))
        result.analysis_details["entropy"] = entropy_result

        # 3. Control flow analysis (CFF, opaque predicates, MBA, VM)
        cf_result = cf_analyzer.analyze()

        if cf_result.cff_detected:
            result.obfuscation_techniques.append(ObfuscationType.CONTROL_FLOW_FLATTENING)
            result.confidence_scores["control_flow_flattening"] = cf_result.cff_confidence
        result.control_flow_flattened = cf_result.cff_detected

        result.vm_detected = cf_result.vm_detected
        result.vm_handler_count = cf_result.vm_handler_count
        if result.vm_detected:
            result.obfuscation_techniques.append(ObfuscationType.VIRTUALIZATION)
            result.confidence_scores["virtualization"] = cf_result.vm_confidence

        result.mba_expressions_found = cf_result.mba_expressions_count
        result.mba_detected = result.mba_expressions_found > 0
        if result.mba_expressions_found > 0:
            result.obfuscation_techniques.append(ObfuscationType.MIXED_BOOLEAN_ARITHMETIC)
            result.confidence_scores["mba"] = min(1.0, result.mba_expressions_found / 10.0)

        result.opaque_predicates_found = cf_result.opaque_predicates_count
        if result.opaque_predicates_found > 0:
            result.obfuscation_techniques.append(ObfuscationType.OPAQUE_PREDICATES)
            result.confidence_scores["opaque_predicates"] = min(1.0, result.opaque_predicates_found / 5.0)

        # 4. Pattern matching (anti-debug, anti-VM)
        pattern_result = pattern_matcher.scan()

        if pattern_result.anti_debug_detected:
            result.obfuscation_techniques.append(ObfuscationType.ANTI_DEBUG)
            result.confidence_scores["anti_debug"] = pattern_result.anti_debug_confidence

        if pattern_result.anti_vm_detected:
            result.obfuscation_techniques.append(ObfuscationType.ANTI_VM)
            result.confidence_scores["anti_vm"] = pattern_result.anti_vm_confidence
        result.anti_analysis_detected = (
            pattern_result.anti_debug_detected or pattern_result.anti_vm_detected
        )

        if pattern_result.string_encryption_detected:
            result.obfuscation_techniques.append(ObfuscationType.STRING_ENCRYPTION)
            result.confidence_scores["string_encryption"] = 0.7

        if pattern_result.import_hiding_detected:
            result.obfuscation_techniques.append(ObfuscationType.IMPORT_HIDING)
            result.confidence_scores["import_hiding"] = 0.7

        # 5. Determine analysis requirements
        result.requires_devirtualization = result.vm_detected or result.packer_detected in [
            PackerType.VMPROTECT,
            PackerType.THEMIDA,
        ]

        result.requires_dynamic_analysis = (
            result.packer_detected != PackerType.NONE
            or entropy_result.is_packed
            or pattern_result.anti_debug_confidence > 0.5
            or pattern_result.anti_vm_confidence > 0.5
        )

        if result.confidence_scores:
            result.confidence_score = max(result.confidence_scores.values())

        logger.info(f"Obfuscation analysis complete: {len(result.obfuscation_techniques)} techniques detected")
        return result

    def detect_custom_virtualizer(self, binary: Binary) -> dict[str, Any]:
        """
        Detect custom virtualization engines.

        Args:
            binary: Binary to analyze

        Returns:
            Dictionary with detection results
        """
        cf_analyzer = ControlFlowAnalyzer(binary)
        return cf_analyzer.detect_custom_virtualizer()

    def detect_code_packing_layers(self, binary: Binary) -> dict[str, Any]:
        """
        Detect multiple packing layers.

        Args:
            binary: Binary to analyze

        Returns:
            Dictionary with layer analysis
        """
        return self.packer_db.detect_packing_layers(binary, self.entropy_analyzer)

    def detect_metamorphic_engine(self, binary: Binary) -> dict[str, Any]:
        """
        Detect metamorphic code generation.

        Args:
            binary: Binary to analyze

        Returns:
            Dictionary with metamorphic analysis
        """
        cf_analyzer = ControlFlowAnalyzer(binary)
        cf_result = cf_analyzer.analyze()

        return {
            "detected": cf_result.metamorphic_detected,
            "confidence": cf_result.metamorphic_confidence,
            "indicators": cf_result.metamorphic_indicators,
            "polymorphic_ratio": cf_result.polymorphic_ratio,
        }

    def get_comprehensive_report(self, binary: Binary) -> dict[str, Any]:
        """
        Generate comprehensive obfuscation analysis report.

        Args:
            binary: Binary to analyze

        Returns:
            Complete analysis report
        """
        report: dict[str, Any] = {
            "timestamp": "",
            "binary_info": {},
            "packer_analysis": {},
            "obfuscation_analysis": {},
            "virtualization_analysis": {},
            "layer_analysis": {},
            "metamorphic_analysis": {},
            "recommendations": [],
        }

        try:
            report["timestamp"] = datetime.datetime.now().isoformat()

            # Basic binary info
            report["binary_info"] = {
                "path": binary.filepath if hasattr(binary, "filepath") else "unknown",
                "format": binary.info.get("bin", {}).get("class", "unknown"),
                "architecture": binary.info.get("bin", {}).get("machine", "unknown"),
                "bits": binary.info.get("bin", {}).get("bits", 0),
            }

            # Comprehensive analysis
            basic_result = self.analyze_binary(binary)
            report["obfuscation_analysis"] = {
                "packer_detected": basic_result.packer_detected.value,
                "obfuscation_techniques": [t.value for t in basic_result.obfuscation_techniques],
                "confidence_scores": basic_result.confidence_scores,
                "vm_detected": basic_result.vm_detected,
                "vm_handler_count": basic_result.vm_handler_count,
                "mba_expressions_found": basic_result.mba_expressions_found,
                "opaque_predicates_found": basic_result.opaque_predicates_found,
                "requires_devirtualization": basic_result.requires_devirtualization,
                "requires_dynamic_analysis": basic_result.requires_dynamic_analysis,
            }

            # Extended analysis
            report["virtualization_analysis"] = self.detect_custom_virtualizer(binary)
            report["layer_analysis"] = self.detect_code_packing_layers(binary)
            report["metamorphic_analysis"] = self.detect_metamorphic_engine(binary)

            # Generate recommendations
            recommendations = []

            if basic_result.vm_detected:
                recommendations.append("VM protection detected - use devirtualization techniques")

            if basic_result.mba_expressions_found > 0:
                recommendations.append("MBA expressions found - apply expression simplification")

            if report["layer_analysis"]["layers_detected"] > 1:
                recommendations.append("Multiple packing layers detected - iterative unpacking required")

            if report["metamorphic_analysis"]["detected"]:
                recommendations.append("Metamorphic code detected - use pattern-based analysis")

            if basic_result.requires_dynamic_analysis:
                recommendations.append("Dynamic analysis recommended for complete deobfuscation")

            report["recommendations"] = recommendations

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            report["errors"] = [str(e)]

        return report
