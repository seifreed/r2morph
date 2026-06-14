"""Model types for anti-analysis bypass detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AntiAnalysisType(Enum):
    """Types of anti-analysis techniques."""

    DEBUGGER_DETECTION = "debugger_detection"
    VM_DETECTION = "vm_detection"
    SANDBOX_DETECTION = "sandbox_detection"
    TIMING_ATTACKS = "timing_attacks"
    PROCESS_INSPECTION = "process_inspection"
    MEMORY_SCANNING = "memory_scanning"
    API_HOOKING_DETECTION = "api_hooking_detection"
    ENVIRONMENT_CHECKS = "environment_checks"
    HARDWARE_FINGERPRINTING = "hardware_fingerprinting"


class BypassTechnique(Enum):
    """Bypass techniques available."""

    ENVIRONMENT_MASKING = "environment_masking"
    API_REDIRECTION = "api_redirection"
    TIMING_MANIPULATION = "timing_manipulation"
    PROCESS_HIDING = "process_hiding"
    REGISTRY_SPOOFING = "registry_spoofing"
    FILE_SYSTEM_HOOKS = "filesystem_hooks"
    NETWORK_ISOLATION = "network_isolation"
    HARDWARE_EMULATION = "hardware_emulation"


@dataclass
class AntiAnalysisPattern:
    """Pattern for detecting anti-analysis techniques."""

    name: str
    technique_type: AntiAnalysisType
    api_calls: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    process_names: list[str] = field(default_factory=list)
    string_patterns: list[str] = field(default_factory=list)
    timing_patterns: list[str] = field(default_factory=list)
    confidence_threshold: float = 0.7


@dataclass
class BypassResult:
    """Result of anti-analysis bypass operation."""

    success: bool
    techniques_applied: list[BypassTechnique] = field(default_factory=list)
    techniques_detected: list[AntiAnalysisType] = field(default_factory=list)
    bypass_confidence: float = 0.0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    environment_state: dict[str, Any] = field(default_factory=dict)
    active_bypasses: dict[str, Any] = field(default_factory=dict)
