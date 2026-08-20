"""Contract tests for pass dependency catalogs."""

from __future__ import annotations

from r2morph.mutations.pass_dependencies import PassDependencyRegistry
from r2morph.mutations.pass_dependency_catalogs import default_pass_dependencies
from r2morph.mutations.pass_dependency_models import DependencyType
from tests.utils.assertions import expect
from tests.utils.field_names import SOURCE_STAGE_KEY, TARGET_STAGE_KEY


def test_default_pass_dependencies_cover_expected_pairs() -> None:
    dependencies = default_pass_dependencies()

    expect(
        any(
            getattr(dep, SOURCE_STAGE_KEY) == "control_flow_flattening"
            and getattr(dep, TARGET_STAGE_KEY) == "block_reordering"
            and dep.dep_type == DependencyType.REQUIRES_ABSENCE
            for dep in dependencies
        )
    )
    expect(any(getattr(dep, SOURCE_STAGE_KEY) == "instruction_expansion" for dep in dependencies))


def test_registry_defaults_match_catalog() -> None:
    registry = PassDependencyRegistry()
    expect(len(registry._dependencies) == len(default_pass_dependencies()))
