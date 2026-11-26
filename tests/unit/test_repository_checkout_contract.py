"""Check that Git preserves bytes used by hash-bound source and evidence."""

from __future__ import annotations

from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_hash_bound_text_files_preserve_platform_artifact_bytes() -> None:
    expect(
        (_ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        == [
            "* text=auto eol=lf",
            "docs/*-windows*.json -text -eol whitespace=cr-at-eol",
        ]
    )
