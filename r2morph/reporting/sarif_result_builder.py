"""Result construction helpers for SARIF formatting."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.sarif_result_builder_helpers import (
    build_code_flows,
    build_mutation_result,
    build_validation_result,
)
from r2morph.reporting.sarif_schema import SARIFResult


class SARIFResultBuilder:
    """Build SARIF results from mutation and validation records."""

    def __init__(
        self,
        mutation_rules: list[dict[str, Any]],
        validation_rules: list[dict[str, Any]],
    ) -> None:
        self._mutation_rules = mutation_rules
        self._validation_rules = validation_rules

    def build_results(self, report_data: Any) -> list[SARIFResult]:
        results: list[SARIFResult] = []

        validation_by_addr: dict[int, list[Any]] = {}
        if report_data.validations:
            for validation in report_data.validations:
                if validation.address is not None and not validation.passed:
                    validation_by_addr.setdefault(validation.address, []).append(validation)

        mutation_results: list[SARIFResult] = []
        if report_data.mutations:
            for mutation in report_data.mutations:
                related = validation_by_addr.get(mutation.address, [])
                result = self._mutation_to_result(mutation, report_data.binary_path, related)
                mutation_results.append(result)

        code_flows = build_code_flows(report_data.mutations or [], report_data.binary_path)
        if code_flows and mutation_results:
            mutation_results[0].code_flows = code_flows

        results.extend(mutation_results)

        if report_data.validations:
            for validation in report_data.validations:
                if not validation.passed:
                    result = self._validation_to_result(validation, report_data.binary_path)
                    results.append(result)

        return results

    def _mutation_to_result(
        self,
        mutation: Any,
        binary_path: str,
        related_validations: list[Any],
    ) -> SARIFResult:
        return build_mutation_result(mutation, binary_path, related_validations)

    def _validation_to_result(self, validation: Any, binary_path: str) -> SARIFResult:
        return build_validation_result(validation, binary_path)
