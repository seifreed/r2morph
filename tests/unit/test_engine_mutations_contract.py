"""Contract tests for engine mutation helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from r2morph.core.engine_mutations import add_mutation, mutations, remove_mutation, resolve_mutation_pass
from r2morph.mutations import NopInsertionPass
from tests.utils.assertions import expect


class _FakePipeline:
    def __init__(self) -> None:
        self.passes: list[object] = []
        self.removed: list[str] = []

    def add_pass(self, mutation: object) -> None:
        self.passes.append(mutation)

    def remove_pass_by_name(self, mutation_name: str) -> None:
        self.removed.append(mutation_name)
        self.passes = [mutation for mutation in self.passes if getattr(mutation, "name", None) != mutation_name]


class _MemoryAwareMutation:
    def __init__(self, name: str = "MemoryAware") -> None:
        self.name = name
        self.constraints: list[float] = []

    def configure_for_memory_constraints(self, factor: float) -> None:
        self.constraints.append(factor)


def test_engine_mutations_manage_pipeline_and_memory_mode() -> None:
    pipeline = _FakePipeline()
    mutation = _MemoryAwareMutation()
    engine = SimpleNamespace(pipeline=pipeline, _memory_efficient_mode=True)

    returned = add_mutation(engine, mutation)

    expect(not (returned is not engine))
    expect(mutations(engine) == [mutation])
    expect(mutation.constraints == [0.4])

    removed = remove_mutation(engine, "MemoryAware")

    expect(not (removed is not engine))
    expect(pipeline.removed == ["MemoryAware"])
    expect(mutations(engine) == [])


def test_engine_mutations_resolve_named_passes() -> None:
    resolved = resolve_mutation_pass("nop")

    expect(isinstance(resolved, NopInsertionPass))

    with pytest.raises(ValueError):
        resolve_mutation_pass("unknown-pass")
