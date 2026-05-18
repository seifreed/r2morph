"""Regression: rollback_to_checkpoint must restore the metrics captured
at checkpoint time.

_create_checkpoint stored ``self.metrics`` by reference. Because
self.metrics is mutated in place every iteration, every checkpoint
aliased the live object, so rollback_to_checkpoint's
``self.metrics = checkpoint["metrics"]`` assigned the (already mutated)
object back to itself -- a no-op that restored nothing. Existing tests
only asserted the True/False return value, never the restored state.

No mocks (CLAUDE.md SS4): a real IterativeSimplifier; no binary needed
for the checkpoint/rollback path.
"""

from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier


def test_rollback_to_checkpoint_restores_metric_snapshot() -> None:
    simplifier = IterativeSimplifier()

    simplifier.metrics.iteration = 5
    simplifier.metrics.simplified_expressions = 2

    checkpoint = simplifier._create_checkpoint({"functions": []})
    simplifier.checkpoints.append(checkpoint)

    # Mutate the live metrics after the checkpoint, as the iteration loop
    # does in place.
    simplifier.metrics.iteration = 99
    simplifier.metrics.simplified_expressions = 77

    assert simplifier.rollback_to_checkpoint() is True
    assert simplifier.metrics.iteration == 5
    assert simplifier.metrics.simplified_expressions == 2
