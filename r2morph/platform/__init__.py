"""
Platform-specific utilities for binary handling.
"""

from r2morph.platform.codesign import CodeSigner
from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler

__all__ = [
    "CodeSigner",
    "PEHandler",
    "ELFHandler",
    "MachOHandler",
]
