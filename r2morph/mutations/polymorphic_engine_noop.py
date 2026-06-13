"""No-op mutation passes used by the polymorphic engine."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.base import MutationPass


class NoOpMutation(MutationPass):
    """No-operation mutation pass for state transitions."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="NoOp", config=config)

    def apply(self, binary: Any) -> dict[str, Any]:
        """Apply no-op mutation."""
        return {"applied": False, "reason": "NoOp mutation"}


class NoOp(MutationPass):
    """No-operation pass for identity transitions."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="NoOp", config=config)

    def apply(self, binary: Any) -> dict[str, Any]:
        # `mutations` must be the list of mutation records (Pipeline does
        # len()/iterates it; base.run only setdefaults it when absent).
        # Returning the int 0 here left a non-list in place and crashed
        # the pipeline with "object of type 'int' has no len()". A no-op
        # contributes zero mutations -> empty list.
        return {"mutations": [], "reason": "NoOp pass"}


__all__ = ["NoOp", "NoOpMutation"]
