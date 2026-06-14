"""Contract tests for analysis cache key helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.core.analysis_cache_keys import build_cache_key, get_entry_path, hash_binary, hash_options


def test_analysis_cache_keys_contract() -> None:
    key = build_cache_key(b"abc", "cfg", {"b": 2, "a": 1})

    assert hash_binary(b"abc") == hash_binary(b"abc")
    assert hash_options({"b": 2, "a": 1}) == hash_options({"a": 1, "b": 2})
    assert key.analysis_type == "cfg"
    assert get_entry_path(Path("/tmp/cache"), key).as_posix().endswith(key.to_path())
