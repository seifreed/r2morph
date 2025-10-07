"""
Relocation management for binary transformations.
"""

from r2morph.relocations.cave_finder import CaveFinder
from r2morph.relocations.manager import RelocationManager
from r2morph.relocations.reference_updater import ReferenceUpdater

__all__ = [
    "RelocationManager",
    "CaveFinder",
    "ReferenceUpdater",
]
