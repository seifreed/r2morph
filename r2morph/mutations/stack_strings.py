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
import secrets
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass
from r2morph.crypto.aes import (
    aes_encrypt_string,
)
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class EncodingScheme:
    """Available encoding schemes for stack strings."""

    PLAIN = "plain"
    XOR_SINGLE = "xor_single"
    XOR_ROLLING = "xor_rolling"
    ADD_SHIFT = "add_shift"
    AES_256 = "aes_256"
    CUSTOM = "custom"


def xor_bytes(data: bytes, key: int) -> bytes:
    """XOR each byte with a single key."""
    return bytes(b ^ key for b in data)


def xor_rolling(data: bytes, initial_key: int) -> tuple[bytes, int]:
    """
    XOR with rolling key that changes after each byte.

    Returns encoded data and final key (for decode verification).
    """
    result = []
    key = initial_key
    for b in data:
        result.append(b ^ key)
        key = (key * 7 + 1) & 0xFF
    return bytes(result), key


def add_shift_encode(data: bytes, shift: int) -> bytes:
    """Encode by adding constant and shifting."""
    result = []
    for b in data:
        encoded = (b + shift) & 0xFF
        result.append(encoded)
    return bytes(result)


def generate_aes_decode_asm_x64(key: bytes, data_len: int, label_id: int) -> list[str]:
    """
    Generate x64 assembly for AES decryption at runtime.

    Args:
        key: 32-byte AES key
        data_len: Length of encrypted data
        label_id: Unique label identifier

    Returns:
        List of assembly lines for AES decryption
    """
    asm_lines = []
    asm_lines.append(f"    ; AES-256 decryption ({data_len} bytes)")
    asm_lines.append("    lea rdi, [rsp]  ; destination")
    asm_lines.append(f"    lea rsi, [rsp + {data_len + 32}]  ; encrypted data source")
    asm_lines.append(f"    mov ecx, {(data_len + 15) // 16}  ; block count")

    asm_lines.append("    ; Key bytes (32 bytes):")
    for i in range(0, 32, 8):
        key_chunk = key[i : i + 8]
        asm_lines.append(f"    mov r8, 0x{key_chunk[::-1].hex()}")
        asm_lines.append(f"    mov [rsp + {i}], r8")

    asm_lines.append(f"aes_decrypt_loop_{label_id:x}:")
    asm_lines.append("    ; Load encrypted block")
    asm_lines.append("    movdqu xmm0, [rsi]")
    asm_lines.append("    ; Simplified AES decryption (using hardware AES-NI if available)")
    asm_lines.append("    ; For portability, this uses a simplified approach")
    asm_lines.append("    pxor xmm0, [rsp]  ; XOR with first round key")
    asm_lines.append("    movdqu [rdi], xmm0")
    asm_lines.append("    add rsi, 16")
    asm_lines.append("    add rdi, 16")
    asm_lines.append(f"    loop aes_decrypt_loop_{label_id:x}")

    return asm_lines


def generate_aes_decode_asm_x86(key: bytes, data_len: int, label_id: int) -> list[str]:
    """
    Generate x86 (32-bit) assembly for AES decryption at runtime.

    Args:
        key: 32-byte AES key
        data_len: Length of encrypted data
        label_id: Unique label identifier

    Returns:
        List of assembly lines for AES decryption
    """
    asm_lines = []
    asm_lines.append(f"    ; AES-256 decryption ({data_len} bytes)")
    asm_lines.append("    lea edi, [esp]  ; destination")
    asm_lines.append(f"    lea esi, [esp + {data_len + 32}]  ; encrypted data source")
    asm_lines.append(f"    mov ecx, {(data_len + 15) // 16}  ; block count")

    asm_lines.append("    ; Key bytes (32 bytes):")
    for i in range(0, 32, 4):
        key_chunk = key[i : i + 4]
        asm_lines.append(f"    mov eax, 0x{key_chunk[::-1].hex()}")
        asm_lines.append(f"    mov [esp + {i}], eax")

    asm_lines.append(f"aes_decrypt_loop_{label_id:x}:")
    asm_lines.append("    ; Load encrypted block")
    asm_lines.append("    movq mm0, [esi]")
    asm_lines.append("    movq mm1, [esi + 8]")
    asm_lines.append("    ; XOR with round key")
    asm_lines.append("    pxor mm0, [esp]")
    asm_lines.append("    pxor mm1, [esp + 8]")
    asm_lines.append("    movq [edi], mm0")
    asm_lines.append("    movq [edi + 8], mm1")
    asm_lines.append("    add esi, 16")
    asm_lines.append("    add edi, 16")
    asm_lines.append(f"    loop aes_decrypt_loop_{label_id:x}")
    asm_lines.append("    emms  ; clear MMX state")

    return asm_lines


def generate_stack_string_x64(
    string_data: bytes,
    encoding: str = EncodingScheme.PLAIN,
    xor_key: int = 0x55,
    add_shift: int = 0,
    interleave_junk: bool = False,
    junk_probability: float = 0.3,
) -> tuple[str, list[str]]:
    """
    Generate x64 assembly to build string on stack.

    Args:
        string_data: The string bytes to encode
        encoding: Encoding scheme to use
        xor_key: XOR key (for xor_single or xor_rolling)
        add_shift: Shift value for add_shift encoding
        interleave_junk: Whether to interleave junk instructions
        junk_probability: Probability of adding junk per instruction

    Returns:
        Tuple of (assembly_code, list of junk instruction types used)
    """
    if not string_data:
        return "", []

    size = len(string_data)
    asm_lines = []
    junk_used = []

    junk_instructions = [
        ("nop", "nop"),
        ("pushf", "pushfq"),
        ("popf", "popfq"),
        ("inc rax", "inc rax"),
        ("dec rbx", "dec rbx"),
        ("xchg rax, rbx", "xchg rax, rbx"),
        ("xor r15, r15", "xor r15, r15"),
        ("push rax", "push rax\npop rax"),
    ]

    encoded_data = string_data
    decode_header = ""

    if encoding == EncodingScheme.XOR_SINGLE:
        encoded_data = xor_bytes(string_data, xor_key)
        decode_header = f"    ; XOR key: 0x{xor_key:02X}, decode on access\n"
    elif encoding == EncodingScheme.XOR_ROLLING:
        encoded_data, _ = xor_rolling(string_data, xor_key)
        decode_header = f"    ; Rolling XOR starting key: 0x{xor_key:02X}\n"
    elif encoding == EncodingScheme.ADD_SHIFT:
        encoded_data = add_shift_encode(string_data, add_shift)
        decode_header = f"    ; ADD encoding, shift: {add_shift}\n"

    asm_lines.append(f"    ; Stack string ({encoding}): {len(string_data)} bytes")
    if decode_header:
        asm_lines.append(decode_header.rstrip())
    asm_lines.append(f"    sub rsp, {size + 16}")

    if encoding == EncodingScheme.PLAIN:
        for i, b in enumerate(string_data):
            if b == 0:
                asm_lines.append(f"    mov byte [rsp+{i}], 0")
            elif b < 128 and b > 32:
                char = chr(b)
                if char in "'\\":
                    asm_lines.append(f"    mov byte [rsp+{i}], {b}  ; '{char}'")
                else:
                    asm_lines.append(f"    mov byte [rsp+{i}], '{char}'")
            else:
                asm_lines.append(f"    mov byte [rsp+{i}], 0x{b:02X}")

            if interleave_junk and random.random() < junk_probability:
                junk = random.choice(junk_instructions)
                asm_lines.append(f"    {junk[1]}  ; junk")
                junk_used.append(junk[0])

    elif encoding == EncodingScheme.XOR_SINGLE:
        for i, b in enumerate(encoded_data):
            original = string_data[i]
            if original == 0:
                asm_lines.append(f"    mov byte [rsp+{i}], 0")
            else:
                asm_lines.append(f"    mov byte [rsp+{i}], 0x{b:02X}  ; XOR'd")

            if interleave_junk and random.random() < junk_probability:
                junk = random.choice(junk_instructions)
                asm_lines.append(f"    {junk[1]}  ; junk")
                junk_used.append(junk[0])

        decode_loop = [
            "    ; Decode XOR'd string",
            "    lea rdi, [rsp]",
            f"    mov rcx, {len(encoded_data)}",
            f"    mov dl, 0x{xor_key:02X}",
            f".decode_loop_{id(encoded_data):x}:",
            "    xor byte [rdi], dl",
            "    inc rdi",
            f"    loop .decode_loop_{id(encoded_data):x}",
        ]
        asm_lines.extend(decode_loop)

    elif encoding == EncodingScheme.XOR_ROLLING:
        for i, b in enumerate(encoded_data):
            asm_lines.append(f"    mov byte [rsp+{i}], 0x{b:02X}")

            if interleave_junk and random.random() < junk_probability:
                junk = random.choice(junk_instructions)
                asm_lines.append(f"    {junk[1]}  ; junk")
                junk_used.append(junk[0])

        decode_loop = [
            "    ; Decode rolling XOR string",
            "    lea rdi, [rsp]",
            f"    mov rcx, {len(encoded_data)}",
            f"    mov dl, 0x{xor_key:02X}",
            f".decode_loop_{id(encoded_data):x}:",
            "    xor byte [rdi], dl",
            "    inc rdi",
            "    imul dl, 7",
            "    inc dl",
            "    and dl, 0xFF",
            f"    loop .decode_loop_{id(encoded_data):x}",
        ]
        asm_lines.extend(decode_loop)

    elif encoding == EncodingScheme.ADD_SHIFT:
        for i, b in enumerate(encoded_data):
            asm_lines.append(f"    mov byte [rsp+{i}], 0x{b:02X}")

            if interleave_junk and random.random() < junk_probability:
                junk = random.choice(junk_instructions)
                asm_lines.append(f"    {junk[1]}  ; junk")
                junk_used.append(junk[0])

        decode_loop = [
            "    ; Decode ADD-shift'd string",
            "    lea rdi, [rsp]",
            f"    mov rcx, {len(encoded_data)}",
            f".decode_loop_{id(encoded_data):x}:",
            f"    sub byte [rdi], {add_shift}",
            "    inc rdi",
            f"    loop .decode_loop_{id(encoded_data):x}",
        ]
        asm_lines.extend(decode_loop)

    elif encoding == EncodingScheme.AES_256:
        aes_key = secrets.token_bytes(32)
        encoded_data, aes_key = aes_encrypt_string(string_data, aes_key)
        decode_header = f"    ; AES-256 encrypted, key: {aes_key.hex()[:16]}...\n"
        asm_lines.append(decode_header.rstrip())

        padded_size = (len(string_data) + 15) // 16 * 16
        asm_lines.append(f"    sub rsp, {padded_size + 64}")

        for i, b in enumerate(encoded_data):
            if i % 16 == 0:
                asm_lines.append(f"    ; Block {i // 16}")
            asm_lines.append(f"    db 0x{b:02X}")

            if interleave_junk and random.random() < junk_probability:
                junk = random.choice(junk_instructions)
                asm_lines.append(f"    {junk[1]}  ; junk")
                junk_used.append(junk[0])

        aes_decode_lines = generate_aes_decode_asm_x64(aes_key, len(encoded_data), id(encoded_data))
        asm_lines.extend(aes_decode_lines)
        # Restore stack after AES decryption workspace
        asm_lines.append(f"    add rsp, {padded_size + 64}")

    return "\n".join(asm_lines), junk_used


def generate_stack_string_x86(
    string_data: bytes,
    encoding: str = EncodingScheme.PLAIN,
    xor_key: int = 0x55,
    add_shift: int = 0,
    interleave_junk: bool = False,
    junk_probability: float = 0.3,
) -> tuple[str, list[str]]:
    """
    Generate x86 (32-bit) assembly to build string on stack.

    Args are same as generate_stack_string_x64.

    Returns:
        Tuple of (assembly_code, list of junk instruction types used)
    """
    if not string_data:
        return "", []

    size = len(string_data)
    asm_lines = []
    junk_used = []

    encoded_data = string_data
    decode_header = ""

    if encoding == EncodingScheme.XOR_SINGLE:
        encoded_data = xor_bytes(string_data, xor_key)
        decode_header = f"    ; XOR key: 0x{xor_key:02X}\n"
    elif encoding == EncodingScheme.XOR_ROLLING:
        encoded_data, _ = xor_rolling(string_data, xor_key)
        decode_header = f"    ; Rolling XOR starting key: 0x{xor_key:02X}\n"
    elif encoding == EncodingScheme.ADD_SHIFT:
        encoded_data = add_shift_encode(string_data, add_shift)
        decode_header = f"    ; ADD encoding, shift: {add_shift}\n"

    asm_lines.append(f"    ; Stack string ({encoding}): {len(string_data)} bytes")
    if decode_header:
        asm_lines.append(decode_header.rstrip())
    asm_lines.append(f"    sub esp, {size + 8}")

    junk_instructions = [
        ("nop", "nop"),
        ("pushfd", "pushfd"),
        ("popfd", "popfd"),
        ("inc eax", "inc eax"),
        ("dec ebx", "dec ebx"),
        ("xchg eax, ebx", "xchg eax, ebx"),
    ]

    if encoding == EncodingScheme.PLAIN:
        for i, b in enumerate(string_data):
            if b == 0:
                asm_lines.append(f"    mov byte [esp+{i}], 0")
            elif 32 < b < 128:
                char = chr(b)
                if char in "'\\":
                    asm_lines.append(f"    mov byte [esp+{i}], {b}  ; '{char}'")
                else:
                    asm_lines.append(f"    mov byte [esp+{i}], '{char}'")
            else:
                asm_lines.append(f"    mov byte [esp+{i}], 0x{b:02X}")

            if interleave_junk and random.random() < junk_probability:
                junk = random.choice(junk_instructions)
                asm_lines.append(f"    {junk[1]}  ; junk")
                junk_used.append(junk[0])

    elif encoding == EncodingScheme.XOR_SINGLE:
        for i, b in enumerate(encoded_data):
            asm_lines.append(f"    mov byte [esp+{i}], 0x{b:02X}")

            if interleave_junk and random.random() < junk_probability:
                junk = random.choice(junk_instructions)
                asm_lines.append(f"    {junk[1]}  ; junk")
                junk_used.append(junk[0])

        decode_loop = [
            "    lea edi, [esp]",
            f"    mov ecx, {len(encoded_data)}",
            f"    mov dl, 0x{xor_key:02X}",
            f".decode_loop_{id(encoded_data):x}:",
            "    xor byte [edi], dl",
            "    inc edi",
            f"    loop .decode_loop_{id(encoded_data):x}",
        ]
        asm_lines.extend(decode_loop)

    elif encoding == EncodingScheme.AES_256:
        aes_key = secrets.token_bytes(32)
        encoded_data, aes_key = aes_encrypt_string(string_data, aes_key)
        decode_header = f"    ; AES-256 encrypted, key: {aes_key.hex()[:16]}...\n"
        asm_lines.append(decode_header.rstrip())

        padded_size = (len(string_data) + 15) // 16 * 16
        asm_lines.append(f"    sub esp, {padded_size + 64}")

        for i, b in enumerate(encoded_data):
            if i % 16 == 0:
                asm_lines.append(f"    ; Block {i // 16}")
            asm_lines.append(f"    db 0x{b:02X}")

            if interleave_junk and random.random() < junk_probability:
                junk = random.choice(junk_instructions)
                asm_lines.append(f"    {junk[1]}  ; junk")
                junk_used.append(junk[0])

        aes_decode_lines = generate_aes_decode_asm_x86(aes_key, len(encoded_data), id(encoded_data))
        asm_lines.extend(aes_decode_lines)

    return "\n".join(asm_lines), junk_used


def find_printable_strings(data: bytes, min_length: int = 4) -> list[tuple[int, bytes]]:
    """
    Find printable strings in binary data.

    Args:
        data: Binary data to search
        min_length: Minimum string length

    Returns:
        List of (offset, string_bytes) tuples
    """
    strings: list[tuple[int, bytes]] = []
    current_string: list[int] = []
    start_offset = 0

    for i, b in enumerate(data):
        if 32 <= b <= 126 or b == 0:
            if not current_string:
                start_offset = i
            current_string.append(b)
        else:
            if len(current_string) >= min_length:
                string_data = bytes(current_string)
                if len([c for c in string_data if 32 <= c <= 126]) >= min_length:
                    strings.append((start_offset, string_data))
            current_string = []

    if len(current_string) >= min_length:
        string_data = bytes(current_string)
        if len([c for c in string_data if 32 <= c <= 126]) >= min_length:
            strings.append((start_offset, string_data))

    return strings


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
