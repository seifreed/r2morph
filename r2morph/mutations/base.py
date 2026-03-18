"""
Base class for mutation passes.
"""

import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PassSupport:
    """Machine-readable support declaration for a mutation pass."""

    formats: tuple[str, ...]
    architectures: tuple[str, ...]
    validators: tuple[str, ...]
    stability: str
    notes: tuple[str, ...] = ()
    validator_capabilities: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MutationRecord:
    """Structured record for a single applied mutation."""

    pass_name: str
    function_address: int | None
    start_address: int
    end_address: int
    original_bytes: str
    mutated_bytes: str
    original_disasm: str
    mutated_disasm: str
    mutation_kind: str
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "applied"
    recorded_after_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        payload = asdict(self)
        original = bytes.fromhex(self.original_bytes)
        mutated = bytes.fromhex(self.mutated_bytes)
        changed_offsets = [
            index for index, (left, right) in enumerate(zip(original, mutated)) if left != right
        ]
        payload["address_range"] = [self.start_address, self.end_address]
        payload["byte_diff_count"] = len(changed_offsets)
        payload["changed_byte_offsets"] = changed_offsets
        payload["byte_diffs"] = [
            {
                "offset": index,
                "original": f"{left:02x}",
                "mutated": f"{right:02x}",
            }
            for index, (left, right) in enumerate(zip(original, mutated))
            if left != right
        ]
        payload["size"] = len(mutated)
        return payload


class MutationPass(ABC):
    """
    Abstract base class for all mutation passes.

    A mutation pass analyzes a binary and applies specific transformations
    while preserving semantic equivalence.

    Subclasses must implement the `apply()` method.

    Attributes:
        name: Name of the mutation pass
        enabled: Whether this pass is enabled
        config: Configuration dictionary for the pass
    """

    def __init__(self, name: str, config: dict[str, Any] | None = None):
        """
        Initialize a mutation pass.

        Args:
            name: Name of this pass
            config: Optional configuration dictionary
        """
        self.name = name
        self.enabled = True
        self.config = config or {}
        self._stats: dict[str, Any] = {}
        self._records: list[MutationRecord] = []
        self._validation_manager: Any | None = None
        self._session: Any | None = None
        self._rollback_policy = "skip-invalid-pass"
        self._checkpoint_per_mutation = False
        self._mutation_counter = 0
        self._run_started_at: float | None = None
        self._support = PassSupport(
            formats=("ELF",),
            architectures=("x86_64",),
            validators=("structural", "runtime"),
            stability="experimental",
        )

    @abstractmethod
    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply mutations to the binary.

        This method must be implemented by subclasses.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        pass

    def run(self, binary: Binary) -> dict[str, Any]:
        """
        Run the mutation pass on a binary.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation results and statistics
        """
        if not self.enabled:
            logger.info(f"Pass {self.name} is disabled, skipping")
            return {"mutations_applied": 0, "skipped": True}

        logger.debug(f"Running mutation pass: {self.name}")
        self._records = []
        self._mutation_counter = 0
        self._run_started_at = time.perf_counter()

        try:
            result = self.apply(binary)
            result.setdefault("mutations", [record.to_dict() for record in self._records])
            result.setdefault("mutations_applied", len(self._records))
            self._stats = result
            return result
        except Exception as e:
            logger.error(f"Error in mutation pass {self.name}: {e}")
            raise
        finally:
            self._run_started_at = None

    def enable(self):
        """Enable this mutation pass."""
        self.enabled = True
        logger.debug(f"Enabled pass: {self.name}")

    def disable(self):
        """Disable this mutation pass."""
        self.enabled = False
        logger.debug(f"Disabled pass: {self.name}")

    def get_stats(self) -> dict[str, Any]:
        """Get statistics from the last run."""
        return self._stats

    def set_support(
        self,
        *,
        formats: tuple[str, ...],
        architectures: tuple[str, ...],
        validators: tuple[str, ...],
        stability: str,
        notes: tuple[str, ...] = (),
        validator_capabilities: dict[str, Any] | None = None,
    ) -> None:
        """Declare pass support information for product reporting."""
        self._support = PassSupport(
            formats=formats,
            architectures=architectures,
            validators=validators,
            stability=stability,
            notes=notes,
            validator_capabilities=validator_capabilities or {},
        )

    def get_support(self) -> PassSupport:
        """Return support declaration for this pass."""
        return self._support

    def bind_runtime(
        self,
        *,
        validation_manager: Any | None = None,
        session: Any | None = None,
        rollback_policy: str = "skip-invalid-pass",
        checkpoint_per_mutation: bool = False,
    ) -> None:
        """Bind runtime services for a pipeline execution."""
        self._validation_manager = validation_manager
        self._session = session
        self._rollback_policy = rollback_policy
        self._checkpoint_per_mutation = checkpoint_per_mutation

    def clear_runtime(self) -> None:
        """Clear runtime services after execution."""
        self._validation_manager = None
        self._session = None
        self._rollback_policy = "skip-invalid-pass"
        self._checkpoint_per_mutation = False

    def _create_mutation_checkpoint(self, label: str) -> str | None:
        """Create a checkpoint for a single mutation when enabled."""
        if not (self._checkpoint_per_mutation and self._session is not None):
            return None

        self._mutation_counter += 1
        checkpoint_name = f"{self.name.lower()}_{label}_{self._mutation_counter}"
        self._session.checkpoint(checkpoint_name, f"{self.name} mutation {self._mutation_counter}")
        return checkpoint_name

    def _record_mutation(
        self,
        *,
        function_address: int | None,
        start_address: int,
        end_address: int,
        original_bytes: bytes,
        mutated_bytes: bytes,
        original_disasm: str,
        mutated_disasm: str,
        mutation_kind: str,
        metadata: dict[str, Any] | None = None,
        status: str = "applied",
    ) -> MutationRecord:
        """Append a structured mutation record to the pass."""
        record = MutationRecord(
            pass_name=self.name,
            function_address=function_address,
            start_address=start_address,
            end_address=end_address,
            original_bytes=original_bytes.hex(),
            mutated_bytes=mutated_bytes.hex(),
            original_disasm=original_disasm,
            mutated_disasm=mutated_disasm,
            mutation_kind=mutation_kind,
            metadata=metadata or {},
            status=status,
            recorded_after_seconds=(
                round(time.perf_counter() - self._run_started_at, 6)
                if self._run_started_at is not None
                else None
            ),
        )
        self._records.append(record)
        return record

    def _reset_random(self) -> int | None:
        """
        Reset the random module for deterministic pass execution when configured.

        Uses pass-specific derived seed if available (_pass_seed), falling back
        to explicit seed in config. This ensures reproducibility while maintaining
        independence between passes when using a base seed.
        """
        if self.config.get("_use_derived_seed") and self.config.get("_pass_seed") is not None:
            derived_seed = int(self.config["_pass_seed"])
            random.seed(derived_seed)
            return derived_seed

        seed = self.config.get("seed")
        if seed is None:
            return None
        random.seed(seed)
        return int(seed)

    def get_records(self) -> list[MutationRecord]:
        """Get mutation records from the last run."""
        return list(self._records)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} enabled={self.enabled}>"
