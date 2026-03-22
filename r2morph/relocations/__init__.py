"""
Relocation management for binary transformations.
"""

from r2morph.relocations.cave_finder import CaveFinder, CodeCave
from r2morph.relocations.cave_injector import (
    CaveCreationOptions,
    CaveType,
    CodeCaveAllocation,
    CodeCaveInjector,
    SectionPermissions,
)
from r2morph.relocations.manager import RelocationManager
from r2morph.relocations.reference_updater import ReferenceUpdater

__all__ = [
    "RelocationManager",
    "CaveFinder",
    "CodeCave",
    "CodeCaveInjector",
    "CodeCaveAllocation",
    "CaveCreationOptions",
    "CaveType",
    "SectionPermissions",
    "ReferenceUpdater",
]
