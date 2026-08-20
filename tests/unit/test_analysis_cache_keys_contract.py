"""Contract tests for analysis cache key helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.core.analysis_cache_keys import build_cache_key, get_entry_path, hash_binary, hash_options
from tests.utils.assertions import expect


def test_analysis_cache_keys_contract() -> None:
    key = build_cache_key(b"abc", "cfg", {"b": 2, "a": 1})

    expect(hash_binary(b"abc") == hash_binary(b"abc"))
    expect(hash_options({"b": 2, "a": 1}) == hash_options({"a": 1, "b": 2}))
    expect(key.analysis_type == "cfg")
    expect(get_entry_path(Path("test-data/cache"), key).as_posix().endswith(key.to_path()))
