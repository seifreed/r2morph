"""Cache storage backend for r2morph analysis results."""

from __future__ import annotations

import io
import json
import pickle
from pathlib import Path
from typing import Any

_SAFE_MODULES: dict[str, set[str]] = {
    "r2morph.core.analysis_cache_models": {"CacheEntry", "CacheKey", "CacheStats"},
    "builtins": {
        "True",
        "False",
        "None",
        "int",
        "float",
        "str",
        "bytes",
        "list",
        "tuple",
        "dict",
        "set",
        "frozenset",
        "bool",
        "complex",
    },
    "collections": {
        "OrderedDict",
        "defaultdict",
        "deque",
        "Counter",
        "namedtuple",
    },
    "datetime": {"datetime", "date", "time", "timedelta", "timezone"},
}


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows known-safe types to be deserialized."""

    def find_class(self, module: str, name: str) -> type:
        allowed = _SAFE_MODULES.get(module)
        if allowed is not None and name in allowed:
            cls = super().find_class(module, name)
            if isinstance(cls, type):
                return cls
            return type(cls)
        raise pickle.UnpicklingError(f"Deserialization of {module}.{name} is not allowed")


def _safe_pickle_load(f: io.BufferedIOBase) -> Any:
    """Load a pickle file using the RestrictedUnpickler for safety."""
    return RestrictedUnpickler(f).load()


class CacheStorage:
    def __init__(self, cache_dir: Path | str | None = None, storage_type: str = "pickle"):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.storage_type = storage_type

    def save(self, key: str, data: Any) -> None:
        if self.cache_dir is None:
            return

        path = self.cache_dir / f"{key}.cache"
        path.parent.mkdir(parents=True, exist_ok=True)

        if self.storage_type == "pickle":
            self._save_pickle(path, data)
        elif self.storage_type == "json":
            self._save_json(path, data)
        else:
            raise ValueError(f"Unknown storage type: {self.storage_type}")

    def load(self, key: str) -> Any | None:
        if self.cache_dir is None:
            return None

        path = self.cache_dir / f"{key}.cache"

        if not path.exists():
            return None

        if self.storage_type == "pickle":
            return self._load_pickle(path)
        elif self.storage_type == "json":
            return self._load_json(path)
        else:
            raise ValueError(f"Unknown storage type: {self.storage_type}")

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

        path = self.cache_dir / f"{key}.cache"
        return path.exists()

    def _save_pickle(self, path: Path, data: Any) -> None:
        with open(path, "wb") as f:
            pickle.dump(data, f)

    def _load_pickle(self, path: Path) -> Any | None:
        try:
            with open(path, "rb") as f:
                return _safe_pickle_load(f)
        except (pickle.PickleError, EOFError, OSError):
            return None

    def _save_json(self, path: Path, data: Any) -> None:
        with open(path, "w") as f:
            json.dump(data, f)

    def _load_json(self, path: Path) -> Any | None:
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
