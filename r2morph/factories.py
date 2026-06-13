"""Factory helpers for core infrastructure objects."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def create_binary_reader(
    r2: Any,
    lazy_load: bool = True,
) -> Any:
    """Create a BinaryReader."""
    from r2morph.core.reader import BinaryReader

    return BinaryReader(r2)


def create_binary_writer(
    r2: Any,
    path: Path,
    writable: bool = False,
) -> Any:
    """Create a BinaryWriter."""
    from r2morph.core.writer import BinaryWriter

    return BinaryWriter(r2, path, writable)


def create_assembly_service() -> Any:
    """Create the shared AssemblyService instance."""
    from r2morph.core.assembly import get_assembly_service

    return get_assembly_service()


def create_memory_manager(
    batch_size: int = 1000,
    low_memory: bool = False,
) -> Any:
    """Create the shared MemoryManager instance."""
    from r2morph.core.memory_manager import get_memory_manager

    return get_memory_manager()


__all__ = [
    "create_binary_reader",
    "create_binary_writer",
    "create_assembly_service",
    "create_memory_manager",
]
