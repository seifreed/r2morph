"""
Export module for r2morph.

Provides functionality to export mutated code in various formats.
"""

from r2morph.export.nasm_export import (
    NASMExporter,
    generate_block_asm,
    generate_final_asm,
    shuffle_blocks,
    remove_redundant_fallthrough,
    assemble_nasm,
    export_shellcode,
)

__all__ = [
    "NASMExporter",
    "generate_block_asm",
    "generate_final_asm",
    "shuffle_blocks",
    "remove_redundant_fallthrough",
    "assemble_nasm",
    "export_shellcode",
]
