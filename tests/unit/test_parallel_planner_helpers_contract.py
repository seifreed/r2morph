from types import SimpleNamespace

from r2morph.core.parallel_planner import PassDependency
from r2morph.core.parallel_planner_helpers import build_conflict_pairs, build_execution_stages


def test_build_execution_stages_respects_dependencies() -> None:
    passes = [SimpleNamespace(name="a"), SimpleNamespace(name="b")]
    dependencies = {"b": PassDependency("b", requires=["a"])}

    stages = build_execution_stages(passes, dependencies)

    assert stages == [["a"], ["b"]]


def test_build_conflict_pairs_detects_either_side_conflict() -> None:
    passes = [SimpleNamespace(name="a"), SimpleNamespace(name="b")]
    dependencies = {"a": PassDependency("a", conflicts=["b"])}

    conflicts = build_conflict_pairs(passes, dependencies)

    assert conflicts == [("a", "b")]
