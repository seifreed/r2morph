"""
Pass dependency tracking system for mutation passes.

Provides dependency management, conflict detection, and ordering validation
for mutation passes to ensure correct pipeline execution.

This module provides:
- Dependency types (requires, conflicts, recommends)
- Pass dependency registry
- Pipeline validation
- Dependency resolution
"""

import logging
from typing import Any

from r2morph.mutations.pass_dependency_catalogs import default_pass_dependencies
from r2morph.mutations.pass_dependency_models import (
    DependencyType,
    DependencyViolation,
    PassDependency,
)

logger = logging.getLogger(__name__)


class PassDependencyRegistry:
    """
    Central registry for pass dependencies.

    Tracks:
    - Required dependencies (pass X must run after pass Y)
    - Conflicts (pass X cannot run after pass Y)
    - Recommendations (pass X works better with pass Y)
    - Absence requirements (pass X requires pass Y not to have run)

    Example:
        registry = PassDependencyRegistry()
        registry.register("control_flow_flattening", "block_reordering",
                         DependencyType.REQUIRES_ABSENCE,
                         "CFF should run before block reordering")
        violations = registry.validate_pipeline(["nop_insertion", "block_reordering"])
    """

    def __init__(self) -> None:
        self._dependencies: list[PassDependency] = []
        self._pass_names: set[str] = set()
        self._initialize_default_dependencies()

    def _initialize_default_dependencies(self) -> None:
        """Initialize with known pass dependencies."""
        for dependency in default_pass_dependencies():
            self.register(
                dependency.source_pass,
                dependency.target_pass,
                dependency.dep_type,
                dependency.reason,
                dependency.optional,
            )

    def register(
        self,
        source_pass: str,
        target_pass: str,
        dep_type: DependencyType,
        reason: str = "",
        optional: bool = False,
    ) -> None:
        """
        Register a dependency between two passes.

        Args:
            source_pass: Name of the pass with the dependency
            target_pass: Name of the pass depended on
            dep_type: Type of dependency
            reason: Human-readable explanation
            optional: Whether this is an optional dependency
        """
        self._pass_names.add(source_pass)
        self._pass_names.add(target_pass)

        dep = PassDependency(
            source_pass=source_pass,
            target_pass=target_pass,
            dep_type=dep_type,
            reason=reason,
            optional=optional,
        )
        self._dependencies.append(dep)
        logger.debug(f"Registered dependency: {dep}")

    def get_dependencies(self, pass_name: str) -> list[PassDependency]:
        """
        Get all dependencies for a pass.

        Args:
            pass_name: Name of the pass

        Returns:
            List of dependencies
        """
        return [dep for dep in self._dependencies if dep.source_pass == pass_name]

    def get_required_dependencies(self, pass_name: str) -> list[PassDependency]:
        """
        Get required dependencies for a pass.

        Args:
            pass_name: Name of the pass

        Returns:
            List of required dependencies
        """
        return [
            dep
            for dep in self._dependencies
            if dep.source_pass == pass_name and dep.dep_type == DependencyType.REQUIRES
        ]

    def get_conflicts(self, pass_name: str) -> list[PassDependency]:
        """
        Get conflicts for a pass.

        Args:
            pass_name: Name of the pass

        Returns:
            List of conflicts
        """
        return [
            dep
            for dep in self._dependencies
            if dep.source_pass == pass_name and dep.dep_type == DependencyType.CONFLICTS_WITH
        ]

    def get_recommendations(self, pass_name: str) -> list[PassDependency]:
        """
        Get recommendations for a pass.

        Args:
            pass_name: Name of the pass

        Returns:
            List of recommendations
        """
        return [
            dep
            for dep in self._dependencies
            if dep.source_pass == pass_name and dep.dep_type == DependencyType.RECOMMENDS
        ]

    def validate_pipeline(self, passes: list[str]) -> list[DependencyViolation]:
        """
        Validate a pipeline of passes.

        Checks:
        - Required dependencies are satisfied
        - Conflicts are avoided
        - Absence requirements are met
        - Recommended order is followed (warnings)

        Args:
            passes: List of pass names in execution order

        Returns:
            List of violations found
        """
        violations: list[DependencyViolation] = []
        executed: set[str] = set()

        for i, pass_name in enumerate(passes):
            deps = self.get_dependencies(pass_name)

            for dep in deps:
                if dep.dep_type == DependencyType.REQUIRES:
                    if dep.target_pass not in executed:
                        if not dep.optional:
                            violations.append(
                                DependencyViolation(
                                    source_pass=pass_name,
                                    target_pass=dep.target_pass,
                                    violation_type="missing_requirement",
                                    message=f"{pass_name} requires {dep.target_pass} to run first"
                                    + (f" ({dep.reason})" if dep.reason else ""),
                                    severity="error",
                                )
                            )

                elif dep.dep_type == DependencyType.CONFLICTS_WITH:
                    if dep.target_pass in executed:
                        violations.append(
                            DependencyViolation(
                                source_pass=pass_name,
                                target_pass=dep.target_pass,
                                violation_type="conflict",
                                message=f"{pass_name} conflicts with already-executed {dep.target_pass}"
                                + (f" ({dep.reason})" if dep.reason else ""),
                                severity="error",
                            )
                        )

                elif dep.dep_type == DependencyType.REQUIRES_ABSENCE:
                    if dep.target_pass in executed:
                        violations.append(
                            DependencyViolation(
                                source_pass=pass_name,
                                target_pass=dep.target_pass,
                                violation_type="absence_required",
                                message=f"{pass_name} requires {dep.target_pass} not to have run"
                                + (f" ({dep.reason})" if dep.reason else ""),
                                severity="error",
                            )
                        )

                elif dep.dep_type == DependencyType.RECOMMENDS:
                    if dep.target_pass not in executed:
                        violations.append(
                            DependencyViolation(
                                source_pass=pass_name,
                                target_pass=dep.target_pass,
                                violation_type="missing_recommendation",
                                message=f"{pass_name} works better after {dep.target_pass}"
                                + (f" ({dep.reason})" if dep.reason else ""),
                                severity="warning",
                            )
                        )

            executed.add(pass_name)

        return violations

    def suggest_order(self, passes: list[str]) -> list[str]:
        """
        Suggest an optimal ordering for a set of passes.

        Args:
            passes: List of pass names (unordered)

        Returns:
            Ordered list of passes that satisfies dependencies
        """
        pass_set = set(passes)
        ordered: list[str] = []
        remaining = set(passes)

        max_iterations = len(passes) * len(passes) + 1
        iteration = 0

        while remaining and iteration < max_iterations:
            iteration += 1
            progress = False

            for pass_name in list(remaining):
                can_add = True

                for dep in self.get_dependencies(pass_name):
                    if dep.dep_type == DependencyType.REQUIRES:
                        if dep.target_pass in pass_set and dep.target_pass not in ordered:
                            if not dep.optional:
                                can_add = False
                                break

                    elif dep.dep_type == DependencyType.REQUIRES_ABSENCE:
                        if dep.target_pass in ordered:
                            can_add = False
                            break

                if can_add:
                    ordered.append(pass_name)
                    remaining.remove(pass_name)
                    progress = True
                    break

            if not progress and remaining:
                remaining_pass = remaining.pop()
                ordered.append(remaining_pass)
                logger.warning(f"Could not satisfy all dependencies for {remaining_pass}")

        return ordered

    def get_pass_info(self, pass_name: str) -> dict[str, Any]:
        """
        Get comprehensive information about a pass's dependencies.

        Args:
            pass_name: Name of the pass

        Returns:
            Dictionary with dependency information
        """
        return {
            "pass_name": pass_name,
            "requires": [dep.to_dict() for dep in self.get_required_dependencies(pass_name)],
            "conflicts": [dep.to_dict() for dep in self.get_conflicts(pass_name)],
            "recommends": [dep.to_dict() for dep in self.get_recommendations(pass_name)],
        }

    def list_all_passes(self) -> list[str]:
        """
        List all passes known to the registry.

        Returns:
            List of pass names
        """
        return sorted(self._pass_names)

    def to_dict(self) -> dict[str, Any]:
        """Convert registry to dictionary representation."""
        return {
            "passes": self.list_all_passes(),
            "dependencies": [dep.to_dict() for dep in self._dependencies],
        }


_pass_dependency_registry: PassDependencyRegistry | None = None


def get_pass_dependency_registry() -> PassDependencyRegistry:
    """
    Get the global pass dependency registry.

    Returns:
        The global PassDependencyRegistry instance
    """
    global _pass_dependency_registry
    if _pass_dependency_registry is None:
        _pass_dependency_registry = PassDependencyRegistry()
    return _pass_dependency_registry


def validate_pipeline_order(passes: list[str]) -> tuple[bool, list[DependencyViolation]]:
    """
    Validate that a pipeline order satisfies all dependencies.

    Args:
        passes: List of pass names in execution order

    Returns:
        Tuple of (is_valid, violations)
    """
    registry = get_pass_dependency_registry()
    violations = registry.validate_pipeline(passes)
    is_valid = all(v.severity != "error" for v in violations)
    return is_valid, violations


def suggest_pipeline_order(passes: list[str]) -> list[str]:
    """
    Suggest optimal ordering for a set of passes.

    Args:
        passes: List of pass names

    Returns:
        Ordered list that satisfies dependencies
    """
    registry = get_pass_dependency_registry()
    return registry.suggest_order(passes)
