from __future__ import annotations

from r2morph.validation.validator_execution_text import hash_text, normalize_output


def test_normalize_output_trims_trailing_whitespace() -> None:
    assert normalize_output("a  \nb\t\n", True) == "a\nb"


def test_hash_text_is_stable() -> None:
    assert hash_text("payload") == hash_text("payload")
