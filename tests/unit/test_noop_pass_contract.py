"""
Regression test: the NoOp pass must honour the apply() result contract.

MutationPass.run / Pipeline treat ``result["mutations"]`` as a list (it is
``len()``-ed and iterated throughout pipeline.py, and base.py only
``setdefault``s it to a list when the key is absent). ``NoOp.apply``
returned ``{"mutations": 0, ...}`` -- an int -- so ``setdefault`` left it
as 0 and ``len(pass_result["mutations"])`` raised
``TypeError: object of type 'int' has no len()``. Adding ``NoOp`` to a
Pipeline therefore broke the whole pipeline (the failure was contained by
the per-pass isolation boundary, and no test exercised NoOp through a
Pipeline, so the suite stayed green). Its sibling ``NoOpMutation`` omits
the key entirely and was unaffected.

Real NoOp pass through the real Pipeline on a real fixtures binary (no
mocks, no monkeypatch). Before the fix the pass failed with the
TypeError; after, it runs and contributes zero mutations.
"""

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.polymorphic_engine import NoOp
from r2morph.pipeline.pipeline import Pipeline

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "optimized_binaries" / "exception_test"


def test_noop_apply_returns_list_mutations(tmp_path: Path) -> None:
    """Direct contract pin: result['mutations'] must be a list."""
    sample = tmp_path / "sample"
    shutil.copy(_FIXTURE, sample)
    binary = Binary(str(sample))
    binary.open()
    try:
        result = NoOp().apply(binary)
    finally:
        binary.close()

    assert isinstance(result["mutations"], list)
    assert result["mutations"] == []


def test_noop_pass_runs_in_pipeline_without_typeerror(tmp_path: Path) -> None:
    sample = tmp_path / "sample"
    shutil.copy(_FIXTURE, sample)

    binary = Binary(str(sample))
    binary.open()
    binary.analyze()
    try:
        pipeline = Pipeline()
        pipeline.add_pass(NoOp())
        result = pipeline.run(binary)
    finally:
        binary.close()

    assert result["failed_passes"] == 0, f"NoOp failed: {result.get('pass_results')}"
    for entry in result.get("pass_results", []):
        if isinstance(entry, dict):
            err = str(entry.get("error") or "")
            assert "has no len()" not in err, f"NoOp mutations-contract regressed: {err}"
