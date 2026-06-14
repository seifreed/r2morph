"""Lock the extended semantic validation model boundary."""

from __future__ import annotations

from r2morph.validation.extended_semantic import ValidationResult as facade_result
from r2morph.validation.extended_semantic_models import ValidationResult as canonical_result


def test_extended_semantic_validation_result_is_canonical_model() -> None:
    assert facade_result is canonical_result
