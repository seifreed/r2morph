from __future__ import annotations

from r2morph.validation.validator_execution_text import hash_text, normalize_output
from tests.utils.assertions import expect


def test_normalize_output_trims_trailing_whitespace() -> None:
    expect(normalize_output("a  \nb\t\n", True) == "a\nb")


def test_hash_text_is_stable() -> None:
    expect(hash_text("payload") == hash_text("payload"))
