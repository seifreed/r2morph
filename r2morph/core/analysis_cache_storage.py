"""Safe structured storage for analysis cache values."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from r2morph.core.analysis_cache_models import CacheEntry, CacheKey, CacheStats

type EncodedValue = bool | int | float | str | list["EncodedValue"] | None

_MAX_NESTING_DEPTH = 64
_TAGGED_VALUE_FIELD_COUNT = 2
_CACHE_KEY_FIELD_COUNT = 4
_CACHE_MODEL_FIELD_COUNT = 7
_SEQUENCE_TAGS = {list: "list", tuple: "tuple", set: "set", frozenset: "frozenset"}


def _check_depth(depth: int) -> None:
    if depth > _MAX_NESTING_DEPTH:
        raise ValueError("Cache value exceeds maximum nesting depth")


def _encode_sequence(value: list[Any] | tuple[Any, ...] | set[Any] | frozenset[Any], depth: int) -> EncodedValue:
    tag = _SEQUENCE_TAGS[type(value)]
    payload: EncodedValue = [_encode(item, depth + 1) for item in value]
    return [tag, payload]


def _encode_model(value: CacheKey | CacheEntry | CacheStats, depth: int) -> EncodedValue:
    if isinstance(value, CacheKey):
        fields: list[Any] = [value.binary_hash, value.analysis_type, value.options_hash, value.version]
        tag = "cache_key"
    elif isinstance(value, CacheEntry):
        fields = [
            value.key,
            value.data,
            value.created_at,
            value.accessed_at,
            value.access_count,
            value.size_bytes,
            value.metadata,
        ]
        tag = "cache_entry"
    else:
        fields = [
            value.hits,
            value.misses,
            value.evictions,
            value.total_size_bytes,
            value.entry_count,
            value.oldest_entry,
            value.newest_entry,
        ]
        tag = "cache_stats"
    payload: EncodedValue = [_encode(field, depth + 1) for field in fields]
    return [tag, payload]


def _encode(value: Any, depth: int = 0) -> EncodedValue:
    _check_depth(depth)
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, bytes):
        return ["bytes", base64.b64encode(value).decode("ascii")]
    if isinstance(value, datetime):
        return ["datetime", value.isoformat()]
    if isinstance(value, CacheKey | CacheEntry | CacheStats):
        return _encode_model(value, depth)
    if isinstance(value, list | tuple | set | frozenset):
        return _encode_sequence(value, depth)
    if isinstance(value, dict):
        pairs: list[EncodedValue] = [[_encode(key, depth + 1), _encode(item, depth + 1)] for key, item in value.items()]
        return ["dict", pairs]
    raise TypeError(f"Unsupported cache value: {type(value).__name__}")


def _decode_sequence(tag: str, payload: EncodedValue, depth: int) -> Any:
    if not isinstance(payload, list):
        raise ValueError(f"Invalid {tag} cache payload")
    items = [_decode(item, depth + 1) for item in payload]
    if tag == "tuple":
        decoded: Any = tuple(items)
    elif tag == "set":
        decoded = set(items)
    elif tag == "frozenset":
        decoded = frozenset(items)
    else:
        decoded = items
    return decoded


def _decode_dict(payload: EncodedValue, depth: int) -> dict[Any, Any]:
    if not isinstance(payload, list):
        raise ValueError("Invalid dict cache payload")
    decoded: dict[Any, Any] = {}
    for pair in payload:
        if not isinstance(pair, list) or len(pair) != _TAGGED_VALUE_FIELD_COUNT:
            raise ValueError("Invalid dict cache item")
        decoded[_decode(pair[0], depth + 1)] = _decode(pair[1], depth + 1)
    return decoded


def _decode_model(tag: str, payload: EncodedValue, depth: int) -> CacheKey | CacheEntry | CacheStats:
    if not isinstance(payload, list):
        raise ValueError(f"Invalid {tag} cache payload")
    values = [_decode(field, depth + 1) for field in payload]
    if tag == "cache_key" and len(values) == _CACHE_KEY_FIELD_COUNT and all(isinstance(item, str) for item in values):
        return CacheKey(*values)
    if tag == "cache_entry" and len(values) == _CACHE_MODEL_FIELD_COUNT:
        key, data, created_at, accessed_at, access_count, size_bytes, metadata = values
        valid = (
            isinstance(key, CacheKey)
            and isinstance(created_at, datetime)
            and isinstance(accessed_at, datetime)
            and isinstance(access_count, int)
            and isinstance(size_bytes, int)
            and isinstance(metadata, dict)
        )
        if valid:
            return CacheEntry(key, data, created_at, accessed_at, access_count, size_bytes, metadata)
    if tag == "cache_stats" and len(values) == _CACHE_MODEL_FIELD_COUNT:
        hits, misses, evictions, total_size, entry_count, oldest, newest = values
        valid_dates = all(item is None or isinstance(item, datetime) for item in (oldest, newest))
        if all(isinstance(item, int) for item in values[:5]) and valid_dates:
            return CacheStats(hits, misses, evictions, total_size, entry_count, oldest, newest)
    raise ValueError(f"Invalid {tag} cache model")


def _decode(value: EncodedValue, depth: int = 0) -> Any:
    _check_depth(depth)
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if not isinstance(value, list) or len(value) != _TAGGED_VALUE_FIELD_COUNT or not isinstance(value[0], str):
        raise ValueError("Invalid tagged cache value")
    tag = value[0]
    payload = value[1]
    if tag in _SEQUENCE_TAGS.values():
        return _decode_sequence(tag, payload, depth)
    if tag == "dict":
        return _decode_dict(payload, depth)
    if tag == "bytes" and isinstance(payload, str):
        return base64.b64decode(payload, validate=True)
    if tag == "datetime" and isinstance(payload, str):
        return datetime.fromisoformat(payload)
    if tag in {"cache_key", "cache_entry", "cache_stats"}:
        return _decode_model(tag, payload, depth)
    raise ValueError(f"Unknown cache value tag: {tag}")


def encode_cache_value(value: Any) -> bytes:
    """Encode a cache value using a closed, non-executable schema."""
    return json.dumps(_encode(value), separators=(",", ":")).encode("utf-8")


def decode_cache_value(payload: bytes) -> Any:
    """Decode a cache value without importing or executing serialized types."""
    decoded = cast(EncodedValue, json.loads(payload))
    return _decode(decoded)


class CacheStorage:
    def __init__(self, cache_dir: Path | str | None = None):
        self.cache_dir = Path(cache_dir) if cache_dir else None

    def save(self, key: str, data: Any) -> None:
        if self.cache_dir is None:
            return
        path = self.cache_dir / f"{key}.cache"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encode_cache_value(data))

    def load(self, key: str) -> Any | None:
        if self.cache_dir is None:
            return None
        path = self.cache_dir / f"{key}.cache"
        if not path.exists():
            return None
        try:
            return decode_cache_value(path.read_bytes())
        except (OSError, TypeError, UnicodeError, ValueError):
            return None

    def delete(self, key: str) -> bool:
        if self.cache_dir is None:
            return False
        path = self.cache_dir / f"{key}.cache"
        if path.exists():
            path.unlink(missing_ok=True)
            return True
        return False

    def exists(self, key: str) -> bool:
        if self.cache_dir is None:
            return False
        return (self.cache_dir / f"{key}.cache").exists()
