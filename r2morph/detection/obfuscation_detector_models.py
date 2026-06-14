"""Model types for obfuscation detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.detection.packer_signatures import PackerType


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
