"""Data models for leak detection."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MemorySnapshot:
    """Snapshot of memory usage at a point in time."""

    timestamp: float
    current_memory_bytes: int
    peak_memory_bytes: int
    object_count: int
    gc_gen0: int
    gc_gen1: int
    gc_gen2: int
    tracer_running: bool


@dataclass
class MemoryLeak:
    """Detected memory leak."""

    leak_type: str  # "memory_growth", "object_leak", "resource_leak"
    description: str
    initial_memory_mb: float
    final_memory_mb: float
    memory_growth_mb: float
    initial_objects: int
    final_objects: int
    object_growth: int
    potential_cause: str | None = None
    traceback: list[str] | None = None


@dataclass
class LeakDetectionResult:
    """Result of leak detection analysis."""

    passed: bool
    leaks_detected: int
    memory_leaks: list[MemoryLeak]
    snapshots: list[MemorySnapshot]
    peak_memory_growth_mb: float
    total_object_growth: int


@dataclass
class ResourceLeak:
    """Detected resource leak."""

    resource_type: str
    description: str
    initial_count: int
    final_count: int
    leaked_count: int


@dataclass
class ResourceLeakTestResult:
    """Result of resource leak testing."""

    passed: bool
    leaks_detected: int
    resource_leaks: list[ResourceLeak]
