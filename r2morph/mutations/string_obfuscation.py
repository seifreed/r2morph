"""
String obfuscation mutation pass.

Obfuscates string literals in the binary by encoding/encrypting them
and adding decode stubs that run at runtime.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import r2morph.core.randomness as random
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)

_ASCII_UPPER_A = 0x41
_ASCII_UPPER_Z = 0x5A
_ASCII_LOWER_A = 0x61
_ASCII_LOWER_Z = 0x7A


class StringObfuscationPass(MutationPass):
    """
    Mutation pass that obfuscates string literals.

    This pass finds string literals in the binary data sections and applies
    encoding/encryption to hide them. Decode stubs are generated to restore
    the strings at runtime.

    Supported encodings:
    - XOR with single-byte key
    - ROT13 for alphabetic strings
    - Byte swap (endianness flip)

    Config options:
        - probability: Probability of obfuscating found string (default: 0.5)
        - max_strings_per_section: Max strings to obfuscate per section (default: 10)
        - encoding: Encoding type ("xor", "rot13", "swap", "random") (default: "random")
        - min_string_length: Minimum string length to obfuscate (default: 4)
        - preserve_null: Whether to preserve null terminators (default: True)
    """

    ENCODINGS: ClassVar[list[str]] = ["xor", "rot13", "swap"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="StringObfuscation", config=config)
        self.probability = self.config.get("probability", 0.5)
        self.max_strings = self.config.get("max_strings_per_section", 10)
        self.encoding = self.config.get("encoding", "random")
        self.min_length = self.config.get("min_string_length", 4)
        self.preserve_null = self.config.get("preserve_null", True)
        self.set_support(
            formats=("ELF", "Mach-O", "PE"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "obfuscates string data in sections",
                "requires decode stub generation",
                "may affect program semantics if strings are constants",
            ),
        )

    def _find_strings(self, binary: Any, section: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Find printable string candidates in a section.

        Args:
            binary: Any instance
            section: Section dictionary from r2

        Returns:
            List of string dictionaries with addr, size, and content
        """
        strings: list[dict[str, Any]] = []
        addr = section.get("addr", section.get("vaddr", 0))
        size = section.get("size", section.get("vsize", 0))

        if size == 0:
            return strings

        try:
            data = binary.read_bytes(addr, size)
        except Exception:
            return strings

        if not data:
            return strings

        current_start = 0
        current_string = bytearray()

        printable_range = range(0x20, 0x7F)

        for i, byte in enumerate(data):
            if byte in printable_range:
                current_string.append(byte)
            elif byte == 0 and current_string:
                if len(current_string) >= self.min_length:
                    strings.append(
                        {
                            "addr": addr + current_start,
                            "size": len(current_string),
                            "content": bytes(current_string).decode("ascii", errors="ignore"),
                            "offset_in_section": current_start,
                        }
                    )
                current_string = bytearray()
                current_start = i + 1
            else:
                current_string = bytearray()
                current_start = i + 1

        return strings

    def _xor_encode(self, data: bytes, key: int) -> bytes:
        """XOR encode data with a single-byte key."""
        return bytes(b ^ key for b in data)

    def _rot13_encode(self, data: bytes) -> bytes:
        """Apply ROT13 encoding to alphabetic characters."""
        result = bytearray()
        for b in data:
            if _ASCII_UPPER_A <= b <= _ASCII_UPPER_Z:
                result.append(((b - _ASCII_UPPER_A + 13) % 26) + _ASCII_UPPER_A)
            elif _ASCII_LOWER_A <= b <= _ASCII_LOWER_Z:
                result.append(((b - _ASCII_LOWER_A + 13) % 26) + _ASCII_LOWER_A)
            else:
                result.append(b)
        return bytes(result)

    def _swap_encode(self, data: bytes) -> bytes:
        """Swap byte pairs (simple encoding)."""
        result = bytearray(len(data))
        for i in range(0, len(data) - 1, 2):
            result[i] = data[i + 1]
            result[i + 1] = data[i]
        if len(data) % 2:
            result[-1] = data[-1]
        return bytes(result)

    def _encode_string(self, data: bytes, encoding: str) -> tuple[bytes, int]:
        """
        Encode string data with specified encoding.

        Args:
            data: Original string bytes
            encoding: Encoding type ("xor", "rot13", "swap")

        Returns:
            Tuple of (encoded_data, key)
        """
        key = 0

        if encoding == "xor":
            key = random.randint(0x01, 0xFF)
            return self._xor_encode(data, key), key
        elif encoding == "rot13":
            return self._rot13_encode(data), 0
        elif encoding == "swap":
            return self._swap_encode(data), 0
        else:
            return data, 0

    @staticmethod
    def _is_unreferenced(binary: Any, address: int) -> bool:
        try:
            references = binary.get_xrefs_to(address)
            if references:
                logger.info("Skipping referenced string at 0x%x", address)
            return not references
        except (AttributeError, OSError, RuntimeError, ValueError) as error:
            logger.warning("Cannot prove string at 0x%x is unreferenced: %s", address, error)
            return False

    @staticmethod
    def _select_data_sections(sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Select data sections across ELF, PE, and radare2's Mach-O names."""
        data_sections = []
        for section in sections:
            section_name = str(section.get("name", "")).lower()
            is_named_data = section_name in (
                ".data",
                ".rodata",
                ".rdata",
                "__data",
                "__const",
                "__cstring",
            )
            is_segmented_macho_data = section_name.endswith((".__data", ".__const", ".__cstring"))
            if is_named_data or is_segmented_macho_data:
                data_sections.append(section)
        if data_sections:
            return data_sections

        # radare2 reports section ``perm`` as a string (e.g. "-rw-").
        return [section for section in sections if "w" in str(section.get("perm", ""))]

    def _obfuscate_string(self, binary: Any, section: dict[str, Any], string_info: dict[str, Any]) -> int:
        """Encode one unreferenced string and return its byte count when applied."""
        bytes_encoded = 0
        if random.random() <= self.probability:
            address = string_info.get("addr")
            size = string_info.get("size")
            content = string_info.get("content", "")
            if isinstance(address, int) and isinstance(size, int) and size > 0:
                mutation_checkpoint = self._create_mutation_checkpoint("string_obfuscate")
                try:
                    encoding = self.encoding
                    if encoding == "random":
                        encoding = random.choice(self.ENCODINGS)

                    original_bytes = binary.read_bytes(address, size)
                    if original_bytes:
                        baseline = {}
                        if self._validation_manager is not None:
                            baseline = self._validation_manager.capture_structural_baseline(binary, None)

                        encoded_bytes_value, key = self._encode_string(original_bytes, encoding)
                        if binary.write_bytes(address, encoded_bytes_value):
                            record = self._record_mutation(
                                function_address=None,
                                start_address=address,
                                end_address=address + size - 1,
                                original_bytes=original_bytes,
                                mutated_bytes=encoded_bytes_value,
                                original_disasm=f'string "{content[:30]}..."',
                                mutated_disasm=f"{encoding}_encoded({key})",
                                mutation_kind="string_obfuscation",
                                metadata={
                                    "encoding": encoding,
                                    "key": key,
                                    "string_length": size,
                                    "original_content_preview": content[:50],
                                    "section": section.get("name", "unknown"),
                                    "structural_baseline": baseline,
                                },
                            )
                            if not self._validate_mutation_or_rollback(binary, record, mutation_checkpoint):
                                logger.info(
                                    "Obfuscated string at 0x%x (%s, key=%d, len=%d)",
                                    address,
                                    encoding,
                                    key,
                                    size,
                                )
                                bytes_encoded = size
                except Exception as error:
                    logger.debug("Failed to obfuscate string at 0x%x: %s", address, error)
        return bytes_encoded

    def _process_section(self, binary: Any, section: dict[str, Any]) -> tuple[bool, int, int]:
        """Process one data section and return candidate, mutation, and byte counts."""
        strings = [
            string for string in self._find_strings(binary, section) if self._is_unreferenced(binary, string["addr"])
        ]
        if not strings:
            return False, 0, 0

        selected = random.sample(strings, min(self.max_strings, len(strings)))
        encoded_sizes = [self._obfuscate_string(binary, section, string) for string in selected]
        applied_sizes = [size for size in encoded_sizes if size > 0]
        return True, len(applied_sizes), sum(applied_sizes)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply string obfuscation to the binary.

        Args:
            binary: Any instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        self._reset_random()

        self._ensure_analyzed(binary)

        sections = binary.get_sections()
        if not sections:
            logger.warning("No sections found in binary")
            return {"mutations_applied": 0, "skipped": True, "reason": "no sections"}

        data_sections = self._select_data_sections(sections)

        strings_obfuscated = 0
        bytes_encoded = 0
        sections_processed = 0

        logger.info(f"String obfuscation: processing {len(data_sections)} data sections")

        for section in data_sections:
            has_candidates, mutation_count, encoded_size = self._process_section(binary, section)
            if not has_candidates:
                continue
            sections_processed += 1
            strings_obfuscated += mutation_count
            bytes_encoded += encoded_size

        logger.info(
            f"String obfuscation complete: {strings_obfuscated} strings, "
            f"{bytes_encoded} bytes in {sections_processed} sections"
        )

        return {
            "mutations_applied": strings_obfuscated,
            "strings_obfuscated": strings_obfuscated,
            "bytes_encoded": bytes_encoded,
            "sections_processed": sections_processed,
            "encoding_types": list(self.ENCODINGS),
            "total_data_sections": len(data_sections),
        }
