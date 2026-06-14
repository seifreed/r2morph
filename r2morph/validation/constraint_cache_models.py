"""Pure data models for constraint caching."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ConstraintCacheEntry:
    """Cached constraint solution."""

    constraint_hash: int
    result: Any
    is_satisfiable: bool
    timestamp: float
    hit_count: int = 0
