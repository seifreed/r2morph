"""Contract tests for pass dependency catalogs."""

from __future__ import annotations

from r2morph.mutations.pass_dependencies import PassDependencyRegistry
from r2morph.mutations.pass_dependency_catalogs import default_pass_dependencies
from r2morph.mutations.pass_dependency_models import DependencyType


def test_default_pass_dependencies_cover_expected_pairs() -> None:
    dependencies = default_pass_dependencies()

    assert any(
        dep.source_pass == "control_flow_flattening"
        and dep.target_pass == "block_reordering"
        and dep.dep_type == DependencyType.REQUIRES_ABSENCE
        for dep in dependencies
    )
    assert any(dep.source_pass == "instruction_expansion" for dep in dependencies)


def test_registry_defaults_match_catalog() -> None:
    registry = PassDependencyRegistry()
    assert len(registry._dependencies) == len(default_pass_dependencies())
