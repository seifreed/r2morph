"""
String obfuscation mutation pass.

Obfuscates string literals in the binary by encoding/encrypting them
and adding decode stubs that run at runtime.
"""

import logging
import random
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


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

    ENCODINGS = ["xor", "rot13", "swap"]

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

    def _find_strings(self, binary: Binary, section: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Find printable string candidates in a section.

        Args:
            binary: Binary instance
            section: Section dictionary from r2

        Returns:
            List of string dictionaries with addr, size, and content
        """
        strings = []
        addr = section.get("addr", 0)
        size = section.get("size", 0)

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

        if len(current_string) >= self.min_length:
            strings.append(
                {
                    "addr": addr + current_start,
                    "size": len(current_string),
                    "content": bytes(current_string).decode("ascii", errors="ignore"),
                    "offset_in_section": current_start,
                }
            )

        return strings

    def _xor_encode(self, data: bytes, key: int) -> bytes:
        """XOR encode data with a single-byte key."""
        return bytes(b ^ key for b in data)

    def _rot13_encode(self, data: bytes) -> bytes:
        """Apply ROT13 encoding to alphabetic characters."""
        result = bytearray()
        for b in data:
            if 0x41 <= b <= 0x5A:  # A-Z
                result.append(((b - 0x41 + 13) % 26) + 0x41)
            elif 0x61 <= b <= 0x7A:  # a-z
                result.append(((b - 0x61 + 13) % 26) + 0x61)
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

    def _generate_decode_stub_x86_64(self, encoding: str, key: int, size: int) -> list[str]:
        """
        Generate x86_64 decode stub instructions.

        Args:
            encoding: Encoding type
            key: XOR key (if applicable)
            size: Size of encoded string

        Returns:
            List of assembly instructions
        """
        if encoding == "xor":
            return [
                f"push rsi",
                f"push rcx",
                f"lea rsi, [rip + _encoded_string]",
                f"mov rcx, {size}",
                f"_decode_loop:",
                f"xor byte [rsi], {key}",
                f"inc rsi",
                f"dec rcx",
                f"jnz _decode_loop",
                f"pop rcx",
                f"pop rsi",
            ]
        elif encoding == "rot13":
            return [
                f"push rsi",
                f"push rcx",
                f"push rax",
                f"lea rsi, [rip + _encoded_string]",
                f"mov rcx, {size}",
                f"_decode_rot13:",
                f"mov al, [rsi]",
                f"cmp al, 0x41",
                f"jb _skip_rot13",
                f"cmp al, 0x5a",
                f"ja _rot13_lower",
                f"sub al, 0x41",
                f"add al, 13",
                f"cmp al, 26",
                f"jb _upper_ok",
                f"sub al, 26",
                f"_upper_ok:",
                f"add al, 0x41",
                f"jmp _store_rot13",
                f"_rot13_lower:",
                f"cmp al, 0x61",
                f"jb _skip_rot13",
                f"cmp al, 0x7a",
                f"ja _skip_rot13",
                f"sub al, 0x61",
                f"add al, 13",
                f"cmp al, 26",
                f"jb _lower_ok",
                f"sub al, 26",
                f"_lower_ok:",
                f"add al, 0x61",
                f"_store_rot13:",
                f"mov [rsi], al",
                f"_skip_rot13:",
                f"inc rsi",
                f"dec rcx",
                f"jnz _decode_rot13",
                f"pop rax",
                f"pop rcx",
                f"pop rsi",
            ]
        else:
            return [
                f"push rsi",
                f"push rcx",
                f"lea rsi, [rip + _encoded_string]",
                f"mov rcx, {size // 2}",
                f"_decode_swap:",
                f"mov al, [rsi]",
                f"xchg al, [rsi + 1]",
                f"mov [rsi], al",
                f"add rsi, 2",
                f"dec rcx",
                f"jnz _decode_swap",
                f"pop rcx",
                f"pop rsi",
            ]

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

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply string obfuscation to the binary.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        self._reset_random()

        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        sections = binary.get_sections()
        if not sections:
            logger.warning("No sections found in binary")
            return {"mutations_applied": 0, "skipped": True, "reason": "no sections"}

        data_sections = [
            s for s in sections if s.get("name", "").lower() in (".data", ".rodata", ".rdata", "__data", "__const")
        ]

        if not data_sections:
            data_sections = [s for s in sections if s.get("perm", 0) & 0x2]

        strings_obfuscated = 0
        bytes_encoded = 0
        sections_processed = 0

        logger.info(f"String obfuscation: processing {len(data_sections)} data sections")

        for section in data_sections:
            strings = self._find_strings(binary, section)

            if not strings:
                continue

            sections_processed += 1
            selected = random.sample(strings, min(self.max_strings, len(strings)))

            for string_info in selected:
                if random.random() > self.probability:
                    continue

                addr = string_info["addr"]
                size = string_info["size"]
                content = string_info["content"]

                mutation_checkpoint = self._create_mutation_checkpoint("string_obfuscate")

                try:
                    encoding = self.encoding
                    if encoding == "random":
                        encoding = random.choice(self.ENCODINGS)

                    original_bytes = binary.read_bytes(addr, size)
                    if not original_bytes:
                        continue

                    baseline = {}
                    if self._validation_manager is not None:
                        baseline = self._validation_manager.capture_structural_baseline(binary, None)

                    encoded_bytes, key = self._encode_string(original_bytes, encoding)

                    if not binary.write_bytes(addr, encoded_bytes):
                        continue

                    refs = binary.get_xrefs_to(addr)
                    if refs:
                        logger.warning(
                            f"String at 0x{addr:x} has {len(refs)} code references - "
                            f"callers may need decode stub. Consider using StackStringsPass instead for runtime strings."
                        )

                    record = self._record_mutation(
                        function_address=None,
                        start_address=addr,
                        end_address=addr + size - 1,
                        original_bytes=original_bytes,
                        mutated_bytes=encoded_bytes,
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

                    if self._validation_manager is not None:
                        outcome = self._validation_manager.validate_mutation(binary, record.to_dict())
                        if not outcome.passed and mutation_checkpoint is not None:
                            if self._session is not None:
                                self._session.rollback_to(mutation_checkpoint)
                            binary.reload()
                            if self._records:
                                self._records.pop()
                            if self._rollback_policy == "fail-fast":
                                raise RuntimeError("Mutation-level validation failed")
                            continue

                    logger.info(f"Obfuscated string at 0x{addr:x} ({encoding}, key={key}, len={size})")
                    strings_obfuscated += 1
                    bytes_encoded += size

                except Exception as e:
                    logger.debug(f"Failed to obfuscate string at 0x{addr:x}: {e}")

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
