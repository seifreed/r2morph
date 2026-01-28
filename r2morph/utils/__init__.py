"""
Utility functions and helpers for r2morph.
"""

from r2morph.utils.dead_code import (
    generate_arm_dead_code,
    generate_arm_dead_code_for_size,
    generate_dead_code_for_arch,
    generate_nop_sequence,
    generate_register_preserving_sequence,
    generate_x86_dead_code,
    generate_x86_dead_code_for_size,
)
from r2morph.utils.entropy import calculate_entropy, calculate_file_entropy
from r2morph.utils.hashing import hash_file
from r2morph.utils.logging import setup_logging

__all__ = [
    "calculate_entropy",
    "calculate_file_entropy",
    "generate_arm_dead_code",
    "generate_arm_dead_code_for_size",
    "generate_dead_code_for_arch",
    "generate_nop_sequence",
    "generate_register_preserving_sequence",
    "generate_x86_dead_code",
    "generate_x86_dead_code_for_size",
    "hash_file",
    "setup_logging",
]
