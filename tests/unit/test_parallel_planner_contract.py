"""Contract tests for the parallel planning layer."""

from __future__ import annotations

from pathlib import Path

from r2morph.core.parallel_planner import (
    DependencyResolver,
    PassDependency,
    PassResult,
    PassStatus,
)
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY


class FakePass:
    def __init__(self, name: str) -> None:
        self.name = name


def test_pass_result_to_dict_serializes_checkpoint_path() -> None:
    result = PassResult(
        **{MUTATION_NAME_KEY: "demo"},
        status=PassStatus.COMPLETED,
        result={"ok": True},
        checkpoint_path=Path("test-data/checkpoint.bin"),
    )

    payload = result.to_dict()

    expect(payload[MUTATION_NAME_KEY] == "demo")
    expect(payload["status"] == "completed")
    expect(payload["checkpoint_path"] == "test-data/checkpoint.bin")


def test_dependency_resolver_orders_required_passes_before_dependents() -> None:
    resolver = DependencyResolver({"b": PassDependency("b", requires=["a"])})
    plan = resolver.resolve([FakePass("a"), FakePass("b")])

    expect(not (plan.get_stage("a") >= plan.get_stage("b")))
