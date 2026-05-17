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

from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class DisassemblerInterface(Protocol):
    """Interface for disassembler operations.

    This protocol defines the contract that any disassembler implementation
    must satisfy. It enables dependency inversion by allowing code to depend
    on this abstraction rather than concrete implementations like r2pipe.

    Example usage:
        def analyze_binary(disasm: DisassemblerInterface, path: Path) -> dict:
            disasm.open(path)
            try:
                info = disasm.cmdj("ij")
                return info
            finally:
                disasm.close()
    """

    def open(self, path: Path, flags: list[str] | None = None) -> None:
        """Open a binary for analysis.

        Args:
            path: Path to the binary file to analyze.
            flags: Optional list of flags to pass to the disassembler.
                   Common flags include ["-2"] for analysis.

        Raises:
            FileNotFoundError: If the binary file does not exist.
            RuntimeError: If the disassembler fails to open the file.
        """
        ...

    def close(self) -> None:
        """Close the connection to the disassembler.

        This should release any resources held by the disassembler.
        Calling close() on an already closed connection should be safe.
        """
        ...

    def cmd(self, command: str) -> str:
        """Execute a command and return string result.

        Args:
            command: The disassembler command to execute.

        Returns:
            The string output from the command.

        Raises:
            RuntimeError: If the disassembler is not open.
        """
        ...

    def cmdj(self, command: str) -> Any:
        """Execute a command and return JSON result.

        This is used for commands that return structured data (typically
        commands ending with 'j' in radare2).

        Args:
            command: The disassembler command to execute.

        Returns:
            The parsed JSON output from the command, typically a dict or list.

        Raises:
            RuntimeError: If the disassembler is not open.
        """
        ...

    def is_open(self) -> bool:
        """Check if connection is open.

        Returns:
            True if the disassembler has an active connection, False otherwise.
        """
        ...


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
class BinaryAccessProtocol(BinaryReaderProtocol, BinaryWriterProtocol, Protocol):
    """Composite protocol for mutation passes that need both read and write access."""

    def assemble(self, instruction: str, function_addr: int | None = None) -> bytes | None:
        """Assemble an instruction to bytes."""
        ...

    def get_arch_info(self) -> dict[str, Any]:
        """Get architecture information."""
        ...

    def is_analyzed(self) -> bool:
        """Check if binary has been analyzed."""
        ...

    def analyze(self, level: str = "aaa") -> Any:
        """Run analysis on the binary."""
        ...

    def reload(self) -> None:
        """Reload the binary connection."""
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

    def configure_for_memory_constraints(self, factor: float) -> None:
        """Adjust pass configuration for memory-efficient mode (0.0-1.0)."""
        ...

    def bind_runtime(
        self,
        *,
        validation_manager: Any | None = None,
        session: Any | None = None,
        rollback_policy: str = "skip-invalid-pass",
        checkpoint_per_mutation: bool = False,
    ) -> None:
        """Bind runtime services for a pipeline execution."""
        ...

    def clear_runtime(self) -> None:
        """Clear runtime services after execution."""
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
class GateFailureReporterProtocol(Protocol):
    """Protocol for gate-failure report summarization and prioritization."""

    def summarize_gate_failures(self, gate_evaluation: dict[str, Any]) -> dict[str, Any]:
        """Build a compact summary of persisted gate failures for reports."""
        ...

    def build_gate_failure_priority(self, gate_failures: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Build an ordered machine-readable priority list for pass gate failures."""
        ...

    def build_gate_failure_severity_priority(self, gate_failures: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Build an ordered severity-first summary for gate failures."""
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


@runtime_checkable
class BinarySignerProtocol(Protocol):
    """Protocol for post-save binary signing/repair on the host platform."""

    def sign_output(self, output_path: Path, config: dict[str, Any]) -> None:
        """Sign or repair the saved binary as the target platform requires."""
        ...


@runtime_checkable
class PipelineProtocol(Protocol):
    """Protocol for the mutation-pass pipeline orchestrator."""

    @property
    def passes(self) -> Sequence[MutationPassProtocol]:
        """Registered mutation passes, in execution order."""
        ...

    def add_pass(self, mutation_pass: MutationPassProtocol) -> "PipelineProtocol":
        """Append a mutation pass to the pipeline."""
        ...

    def remove_pass_by_name(self, name: str) -> None:
        """Remove every registered pass whose name matches ``name``."""
        ...

    def run(
        self,
        binary: Any,
        *,
        session: Any | None = None,
        validation_manager: Any | None = None,
        runtime_validator: Any | None = None,
        runtime_validate_per_pass: bool = False,
        rollback_policy: str = "skip-invalid-pass",
        checkpoint_per_mutation: bool = False,
    ) -> dict[str, Any]:
        """Execute every registered pass on the binary and return statistics."""
        ...


__all__ = [
    "DisassemblerInterface",
    "BinaryReaderProtocol",
    "BinaryWriterProtocol",
    "BinaryAccessProtocol",
    "AssemblyServiceProtocol",
    "MemoryManagerProtocol",
    "ReportEmitterProtocol",
    "BinarySignerProtocol",
    "MutationPassProtocol",
    "PipelineProtocol",
    "ValidatorProtocol",
    "ConsoleRendererProtocol",
    "GateEvaluatorProtocol",
    "GateFailureReporterProtocol",
    "SummaryAggregatorProtocol",
]
