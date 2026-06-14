"""Data models for enhanced binary analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisOptions:
    """Options for the analysis orchestrator."""

    verbose: bool = False
    detect_only: bool = False
    symbolic: bool = False
    dynamic: bool = False
    devirt: bool = False
    iterative: bool = False
    rewrite: bool = False
    bypass: bool = False
    max_functions: int = 5
    max_iterations: int = 5
    timeout: int = 60


@dataclass
class AnalysisResults:
    """Container for all analysis results."""

    detection_result: Any = None
    custom_vm: dict[str, Any] = field(default_factory=dict)
    layers: dict[str, Any] = field(default_factory=dict)
    metamorphic: dict[str, Any] = field(default_factory=dict)
    cfo_reduction: int = 0
    iterative_result: dict[str, Any] | None = None
    vm_handlers: int = 0
    rewrite_output: str | None = None
    report: dict[str, Any] | None = None

