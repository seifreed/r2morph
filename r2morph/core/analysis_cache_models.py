"""Cache identity and entry models for analysis cache storage."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CacheKey:
    binary_hash: str
    analysis_type: str
    options_hash: str
    version: str = "0.2.0"

    def to_string(self) -> str:
        combined = f"{self.binary_hash}:{self.analysis_type}:{self.options_hash}:{self.version}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def to_path(self) -> str:
        h = self.to_string()
        return f"{h[:2]}/{h[2:4]}/{h}.cache"


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_size_bytes: int = 0
    entry_count: int = 0
    oldest_entry: datetime | None = None
    newest_entry: datetime | None = None

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "total_size_bytes": self.total_size_bytes,
            "entry_count": self.entry_count,
            "hit_rate": self.hit_rate,
            "oldest_entry": self.oldest_entry.isoformat() if self.oldest_entry else None,
            "newest_entry": self.newest_entry.isoformat() if self.newest_entry else None,
        }


@dataclass
class CacheEntry:
    key: CacheKey
    data: Any
    created_at: datetime = field(default_factory=datetime.now)
    accessed_at: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    size_bytes: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        self.accessed_at = datetime.now()
        self.access_count += 1


def compute_binary_hash(binary_path: str | Path) -> str:
    path = Path(binary_path)
    sha256 = hashlib.sha256()

    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()[:64]


def compute_partial_hash(binary_path: str | Path, offset: int, size: int) -> str:
    path = Path(binary_path)
    sha256 = hashlib.sha256()

    with open(path, "rb") as handle:
        handle.seek(offset)
        sha256.update(handle.read(size))

    return sha256.hexdigest()[:32]
