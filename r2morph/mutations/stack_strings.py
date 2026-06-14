"""
Stack Strings - Hide static strings by constructing them on the stack.

Transforms static string literals into dynamic stack construction,
evading string detection in static analysis and making strings
harder to find in memory dumps.

Example transformation:

    Original:
        push "Hello"
        push "Hello World"
        call printf

    Transformed:
        sub rsp, 12       ; allocate space
        mov byte [rsp+0], 'H'
        mov byte [rsp+1], 'e'
        mov byte [rsp+2], 'l'
        mov byte [rsp+3], 'l'
        mov byte [rsp+4], 'o'
        mov byte [rsp+5], ' '
        mov byte [rsp+6], 'W'
        ...               ; build on stack runtime
        lea rcx, [rsp]    ; pointer to constructed string
        call printf
        add rsp, 12       ; cleanup

Advanced techniques:
    - XOR encryption with single key
    - XOR with rolling key (key changes each byte)
    - Custom encoding schemes
    - Interleaved construction (mix with junk instructions)
"""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.mutations.base import MutationPass
from r2morph.mutations.stack_strings_helpers import (
    EncodingScheme,
    _add_shift_decode_loop_x64,
    _format_plain_stack_byte,
    _xor_rolling_decode_loop_x64,
    _xor_single_decode_loop_x64,
    add_shift_encode,
    find_printable_strings,
    generate_aes_decode_asm_x64,
    generate_aes_decode_asm_x86,
    generate_stack_string_x64,
    generate_stack_string_x86,
    xor_bytes,
    xor_rolling,
)

logger = logging.getLogger(__name__)


class StackStringsPass(MutationPass):
    """
    Mutation pass that transforms static strings into stack-built strings.

    Finds string literals in the binary and replaces them with
    dynamically constructed strings on the stack, making them harder
    to detect statically.

    Config options:
        - probability: Probability of transforming each string (default: 0.5)
        - min_length: Minimum string length to transform (default: 4)
        - max_length: Maximum string length to transform (default: 256)
        - encoding: Encoding scheme ("plain", "xor_single", "xor_rolling", "add_shift")
        - interleave_junk: Add junk instructions between movs (default: True)
        - junk_probability: Probability of junk instruction per mov (default: 0.2)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="StackStrings", config=config)
        self.probability = self.config.get("probability", 0.5)
        self.min_length = self.config.get("min_length", 4)
        self.max_length = self.config.get("max_length", 256)
        self.encoding = self.config.get("encoding", EncodingScheme.XOR_SINGLE)
        self.interleave_junk = self.config.get("interleave_junk", True)
        self.junk_probability = self.config.get("junk_probability", 0.2)
        self.set_support(
            formats=("ELF", "PE", "Mach-O"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "transforms static strings to stack-constructed",
                "supports multiple encoding schemes",
                "can interleave junk instructions",
            ),
        )

    def _find_strings_in_section(self, binary: Any, section: dict[str, Any]) -> list[dict[str, Any]]:
        """Find strings in a binary section."""
        strings: list[dict[str, Any]] = []
        addr = section.get("addr", 0)
        size = section.get("size", 0)

        if size == 0 or not section.get("name", "").startswith("."):
            return strings

        try:
            data = binary.read_bytes(addr, size)
            found = find_printable_strings(data, self.min_length)

            for offset, string_data in found:
                if len(string_data) > self.max_length:
                    continue
                if len(string_data) < self.min_length:
                    continue

                strings.append(
                    {
                        "address": addr + offset,
                        "size": len(string_data),
                        "data": string_data,
                        "section": section.get("name", "unknown"),
                        "preview": string_data[:50].decode("utf-8", errors="replace"),
                    }
                )
        except Exception as e:
            logger.debug(f"Failed to read section {section.get('name')}: {e}")

        return strings

    def _generate_stack_string_asm(self, string_data: bytes, arch: str = "x64") -> tuple[str, list[str]]:
        """Generate assembly for stack string construction."""
        xor_key = random.randint(0x10, 0xEF)
        add_shift = random.randint(1, 50)

        generator = generate_stack_string_x64 if arch == "x64" else generate_stack_string_x86

        return generator(
            string_data,
            encoding=self.encoding,
            xor_key=xor_key,
            add_shift=add_shift,
            interleave_junk=self.interleave_junk,
            junk_probability=self.junk_probability,
        )

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply stack string transformation.

        Args:
            binary: Any to transform

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying stack strings transformation")

        all_strings = []
        transformed_count = 0
        skipped_count = 0

        try:
            sections = binary.r2.cmdj("iSj") or []
        except Exception as e:
            logger.warning(f"Failed to get sections: {e}")
            sections = []

        for section in sections:
            if not section.get("name", "").startswith("."):
                continue

            strings = self._find_strings_in_section(binary, section)
            all_strings.extend(strings)

        logger.info(f"Found {len(all_strings)} strings")

        for string_info in all_strings:
            if random.random() > self.probability:
                skipped_count += 1
                continue

            string_data = string_info.get("data", b"")
            if not string_data:
                continue

            arch_info = binary.get_arch_info()
            arch = "x64" if arch_info.get("arch") in ("x86_64", "x64", "amd64") else "x86"
            asm_code, junk_used = self._generate_stack_string_asm(string_data, arch)

            transformed_count += 1
            logger.debug(f"Transformed string at 0x{string_info['address']:x}")

        return {
            "strings_found": len(all_strings),
            "strings_transformed": transformed_count,
            "strings_skipped": skipped_count,
            "encoding_used": self.encoding,
            "junk_interleaved": self.interleave_junk,
        }

    def preview_string(self, string: str, arch: str = "x64") -> str:
        """
        Preview what a string would look like after transformation.

        Args:
            string: String to preview
            arch: Target architecture

        Returns:
            Assembly code preview
        """
        string_data = string.encode("utf-8") + b"\x00"
        asm, _ = self._generate_stack_string_asm(string_data, arch)
        return asm


__all__ = [
    "EncodingScheme",
    "StackStringsPass",
    "_add_shift_decode_loop_x64",
    "_format_plain_stack_byte",
    "_xor_rolling_decode_loop_x64",
    "_xor_single_decode_loop_x64",
    "add_shift_encode",
    "find_printable_strings",
    "generate_aes_decode_asm_x64",
    "generate_aes_decode_asm_x86",
    "generate_stack_string_x64",
    "generate_stack_string_x86",
    "xor_bytes",
    "xor_rolling",
]
