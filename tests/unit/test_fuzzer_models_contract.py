from __future__ import annotations

from r2morph.validation import FuzzResult as PublicFuzzResult
from r2morph.validation.fuzzer import FuzzResult as LegacyFuzzResult
from r2morph.validation.fuzzer_models import FuzzResult as ModelFuzzResult


def test_fuzz_result_is_reexported_from_validation_package() -> None:
    assert PublicFuzzResult is ModelFuzzResult


def test_fuzz_result_is_compatible_through_legacy_fuzzer_module() -> None:
    assert LegacyFuzzResult is ModelFuzzResult
