"""Contract tests for the parallel planning layer."""

from __future__ import annotations

from pathlib import Path

from r2morph.core.parallel_planner import (
    DependencyResolver,
    PassDependency,
    PassResult,
    PassStatus,
)


class FakePass:
    def __init__(self, name: str) -> None:
        self.name = name


def test_pass_result_to_dict_serializes_checkpoint_path() -> None:
    result = PassResult(
        pass_name="demo",
        status=PassStatus.COMPLETED,
        result={"ok": True},
        checkpoint_path=Path("/tmp/checkpoint.bin"),
    )

    payload = result.to_dict()

    assert payload["pass_name"] == "demo"
    assert payload["status"] == "completed"
    assert payload["checkpoint_path"] == "/tmp/checkpoint.bin"


def test_dependency_resolver_orders_required_passes_before_dependents() -> None:
    resolver = DependencyResolver({"b": PassDependency("b", requires=["a"] )})
    plan = resolver.resolve([FakePass("a"), FakePass("b")])

    assert plan.get_stage("a") < plan.get_stage("b")
