"""Cache key and path helpers for analysis cache."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from r2morph.core.analysis_cache_models import CacheKey


def hash_binary(binary_data: bytes) -> str:
    return hashlib.sha256(binary_data).hexdigest()[:64]


def hash_options(options: dict[str, Any]) -> str:
    opts_str = json.dumps(options, sort_keys=True)
    return hashlib.sha256(opts_str.encode()).hexdigest()[:16]


def get_entry_path(cache_dir: Path, key: CacheKey) -> Path:
    return cache_dir / key.to_path()


def build_cache_key(binary_data: bytes, analysis_type: str, options: dict[str, Any] | None = None) -> CacheKey:
    options = options or {}
    return CacheKey(
        binary_hash=hash_binary(binary_data),
        analysis_type=analysis_type,
        options_hash=hash_options(options),
    )
