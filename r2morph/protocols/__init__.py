"""
Abstract protocols for dependency inversion following SOLID principles.

This module defines Protocol interfaces that allows the codebase to depend on
abstractions rather than concrete implementations, achieving 100% DIP compliance.

Usage:
    from r2morph.protocols import BinaryReaderProtocol, BinaryWriterProtocol

    class MyReader(BinaryReaderProtocol):
        def read_bytes(self, address: int, size: int) -> bytes:
            # implementation
            pass
"""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class BinaryReaderProtocol(Protocol):
    """Protocol for binary reading operations."""

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from binary at virtual address."""
        ...

    def get_functions(self) -> list[dict[str, Any]]:
        """Get list of functions in the binary."""
        ...

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        """Get disassembly of a function at given address."""
        ...

    def get_basic_blocks(self, address: int) -> list[dict[str, Any]]:
        """Get basic blocks for a function at given address."""
        ...

    def get_sections(self) -> list[dict[str, Any]]:
        """Get sections from the binary."""
        ...

    def get_arch_info(self) -> dict[str, Any]:
        """Get architecture information from the binary."""
        ...


@runtime_checkable
class BinaryWriterProtocol(Protocol):
    """Protocol for binary writing operations."""

    def write_bytes(self, address: int, data: bytes) -> bool:
        """Write bytes to binary at specified address."""
        ...

    def nop_fill(self, address: int, size: int) -> bool:
        """Fill a region with NOPs."""
        ...

    def save(self, output_path: str | None = None) -> None:
        """Save modified binary to file."""
        ...


@runtime_checkable
class AssemblyServiceProtocol(Protocol):
    """Protocol for assembly services."""

    def assemble(self, instruction: str, function_addr: int | None = None) -> bytes | None:
        """Assemble an instruction to bytes."""
        ...


@runtime_checkable
class MemoryManagerProtocol(Protocol):
    """Protocol for memory management services."""

    def track_mutation(self) -> int:
        """Track mutation count for batch processing."""
        ...

    def get_mutation_counter(self) -> int:
        """Get the current mutation counter."""
        ...

    def reset_mutation_counter(self) -> None:
        """Reset the mutation counter."""
        ...


@runtime_checkable
class ReportEmitterProtocol(Protocol):
    """Protocol for report emission."""

    def emit_report_payload(
        self,
        filtered_payload: dict[str, Any],
        output: str | None,
        summary_only: bool,
    ) -> None:
        """Write and/or print a filtered report payload."""
        ...

    def enforce_report_requirements(
        self,
        require_results: bool,
        severity_rows: list[dict[str, Any]],
        min_severity_rank: int | None,
        mutation_count: int,
        **kwargs: Any,
    ) -> None:
        """Apply report exit-code policy for empty views."""
        ...


@runtime_checkable
class MutationPassProtocol(Protocol):
    """Protocol for mutation passes.

    Matches the actual MutationPass.apply() signature:
        apply(binary) -> dict with mutation statistics
    """

    name: str
    enabled: bool
    config: dict[str, Any]

    def apply(self, binary: Any) -> dict[str, Any]:
        """Apply the mutation pass to a binary."""
        ...

    def run(self, binary: Any) -> dict[str, Any]:
        """Run the pass with lifecycle management (reset, apply, record)."""
        ...

    def get_support(self) -> Any:
        """Get support information for this pass."""
        ...


@runtime_checkable
class ValidatorProtocol(Protocol):
    """Protocol for validators."""

    def validate(
        self,
        binary: Any,
        function: Any,
        mutations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Validate mutations against original binary."""
        ...


@runtime_checkable
class ConsoleRendererProtocol(Protocol):
    """Protocol for console rendering services."""

    def render_report(self, payload: dict[str, Any], **kwargs: Any) -> None:
        """Render a complete report payload."""
        ...

    def render_summary(self, summary: dict[str, Any]) -> None:
        """Render just the summary section."""
        ...


@runtime_checkable
class GateEvaluatorProtocol(Protocol):
    """Protocol for gate evaluation services."""

    def check_pass_severity_requirements(
        self,
        severity_rows: list[dict[str, Any]],
        requirements: list[tuple[str, str, int]],
    ) -> tuple[bool, list[str]]:
        """Check whether all required passes meet their minimum allowed severity rank."""
        ...

    def summarize_gate_failures(
        self,
        gate_evaluation: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a compact summary of persisted gate failures for reports."""
        ...


@runtime_checkable
class SummaryAggregatorProtocol(Protocol):
    """Protocol for summary aggregation services."""

    def summarize_from_mutations(
        self,
        mutations: list[dict[str, Any]],
    ) -> tuple[dict[str, int], list[dict[str, Any]], dict[str, dict[str, int]]]:
        """Build global and per-pass symbolic status summaries."""
        ...

    def summarize_pass_evidence(
        self,
        pass_results: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Aggregate per-pass evidence summaries for tooling."""
        ...


__all__ = [
    "BinaryReaderProtocol",
    "BinaryWriterProtocol",
    "AssemblyServiceProtocol",
    "MemoryManagerProtocol",
    "ReportEmitterProtocol",
    "MutationPassProtocol",
    "ValidatorProtocol",
    "ConsoleRendererProtocol",
    "GateEvaluatorProtocol",
    "SummaryAggregatorProtocol",
]
