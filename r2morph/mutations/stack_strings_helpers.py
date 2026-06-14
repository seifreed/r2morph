"""Pure helpers for stack string encoding and assembly generation."""

from __future__ import annotations

import random
import secrets

from r2morph.crypto.aes import aes_encrypt_string


class EncodingScheme:
    """Available encoding schemes for stack strings."""

    PLAIN = "plain"
    XOR_SINGLE = "xor_single"
    XOR_ROLLING = "xor_rolling"
    ADD_SHIFT = "add_shift"
    AES_256 = "aes_256"
    CUSTOM = "custom"


_JUNK_INSTRUCTIONS_X64 = [
    ("nop", "nop"),
    ("pushf", "pushfq"),
    ("popf", "popfq"),
    ("inc rax", "inc rax"),
    ("dec rbx", "dec rbx"),
    ("xchg rax, rbx", "xchg rax, rbx"),
    ("xor r15, r15", "xor r15, r15"),
    ("push rax", "push rax\npop rax"),
]
_JUNK_INSTRUCTIONS_X86 = [
    ("nop", "nop"),
    ("pushfd", "pushfd"),
    ("popfd", "popfd"),
    ("inc eax", "inc eax"),
    ("dec ebx", "dec ebx"),
    ("xchg eax, ebx", "xchg eax, ebx"),
]


def _append_optional_junk(
    asm_lines: list[str],
    junk_used: list[str],
    junk_table: list[tuple[str, str]],
    *,
    interleave_junk: bool,
    junk_probability: float,
) -> None:
    """Append one random junk instruction from junk_table with junk_probability."""
    if interleave_junk and random.random() < junk_probability:
        junk = random.choice(junk_table)
        asm_lines.append(f"    {junk[1]}  ; junk")
        junk_used.append(junk[0])


def _format_plain_stack_byte(offset: int, byte: int, stack_reg: str) -> str:
    """Format a single plain (unencoded) byte store onto the stack."""
    if byte == 0:
        return f"    mov byte [{stack_reg}+{offset}], 0"
    if 32 < byte < 128:
        char = chr(byte)
        if char in "'\\":
            return f"    mov byte [{stack_reg}+{offset}], {byte}  ; '{char}'"
        return f"    mov byte [{stack_reg}+{offset}], '{char}'"
    return f"    mov byte [{stack_reg}+{offset}], 0x{byte:02X}"


def _xor_single_decode_loop_x64(length: int, xor_key: int, label_id: int) -> list[str]:
    """Build the x64 runtime decode loop for a single-key XOR'd stack string."""
    return [
        "    ; Decode XOR'd string",
        "    lea rdi, [rsp]",
        f"    mov rcx, {length}",
        f"    mov dl, 0x{xor_key:02X}",
        f".decode_loop_{label_id:x}:",
        "    xor byte [rdi], dl",
        "    inc rdi",
        f"    loop .decode_loop_{label_id:x}",
    ]


def _xor_rolling_decode_loop_x64(length: int, xor_key: int, label_id: int) -> list[str]:
    """Build the x64 runtime decode loop for a rolling-key XOR'd stack string."""
    return [
        "    ; Decode rolling XOR string",
        "    lea rdi, [rsp]",
        f"    mov rcx, {length}",
        f"    mov dl, 0x{xor_key:02X}",
        f".decode_loop_{label_id:x}:",
        "    xor byte [rdi], dl",
        "    inc rdi",
        "    imul dl, 7",
        "    inc dl",
        "    and dl, 0xFF",
        f"    loop .decode_loop_{label_id:x}",
    ]


def _add_shift_decode_loop_x64(length: int, add_shift: int, label_id: int) -> list[str]:
    """Build the x64 runtime decode loop for an ADD-shift encoded stack string."""
    return [
        "    ; Decode ADD-shift'd string",
        "    lea rdi, [rsp]",
        f"    mov rcx, {length}",
        f".decode_loop_{label_id:x}:",
        f"    sub byte [rdi], {add_shift}",
        "    inc rdi",
        f"    loop .decode_loop_{label_id:x}",
    ]


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
    """Generate x64 assembly for AES decryption at runtime."""
    asm_lines = []
    asm_lines.append(f"    ; AES_256 (keyed-XOR obfuscation) decode ({data_len} bytes)")
    asm_lines.append("    lea rdi, [rsp]  ; destination")
    asm_lines.append(f"    lea rsi, [rsp + {data_len + 32}]  ; encrypted data source")
    asm_lines.append(f"    mov ecx, {(data_len + 15) // 16}  ; block count")

    asm_lines.append("    ; Key bytes (32 bytes):")
    for i in range(0, 32, 8):
        key_chunk = key[i : i + 8]
        asm_lines.append(f"    mov r8, 0x{key_chunk[::-1].hex()}")
        asm_lines.append(f"    mov [rsp + {i}], r8")

    asm_lines.append("    ; keystream = key[0:16] ^ key[16:32]  (matches aes._derive_block_keystream)")
    asm_lines.append("    movdqu xmm1, [rsp]")
    asm_lines.append("    movdqu xmm2, [rsp + 16]")
    asm_lines.append("    pxor xmm1, xmm2")
    asm_lines.append(f"aes_decrypt_loop_{label_id:x}:")
    asm_lines.append("    ; Decode block: cipher ^ keystream (involutive)")
    asm_lines.append("    movdqu xmm0, [rsi]")
    asm_lines.append("    pxor xmm0, xmm1")
    asm_lines.append("    movdqu [rdi], xmm0")
    asm_lines.append("    add rsi, 16")
    asm_lines.append("    add rdi, 16")
    asm_lines.append(f"    loop aes_decrypt_loop_{label_id:x}")

    return asm_lines


def generate_aes_decode_asm_x86(key: bytes, data_len: int, label_id: int) -> list[str]:
    """Generate x86 (32-bit) assembly for AES decryption at runtime."""
    asm_lines = []
    asm_lines.append(f"    ; AES_256 (keyed-XOR obfuscation) decode ({data_len} bytes)")
    asm_lines.append("    lea edi, [esp]  ; destination")
    asm_lines.append(f"    lea esi, [esp + {data_len + 32}]  ; encrypted data source")
    asm_lines.append(f"    mov ecx, {(data_len + 15) // 16}  ; block count")

    asm_lines.append("    ; Key bytes (32 bytes):")
    for i in range(0, 32, 4):
        key_chunk = key[i : i + 4]
        asm_lines.append(f"    mov eax, 0x{key_chunk[::-1].hex()}")
        asm_lines.append(f"    mov [esp + {i}], eax")

    asm_lines.append("    ; keystream halves = key[0:16] ^ key[16:32]  (matches aes._derive_block_keystream)")
    asm_lines.append("    movq mm2, [esp]")
    asm_lines.append("    pxor mm2, [esp + 16]")
    asm_lines.append("    movq mm3, [esp + 8]")
    asm_lines.append("    pxor mm3, [esp + 24]")
    asm_lines.append(f"aes_decrypt_loop_{label_id:x}:")
    asm_lines.append("    ; Decode block: cipher ^ keystream (involutive)")
    asm_lines.append("    movq mm0, [esi]")
    asm_lines.append("    movq mm1, [esi + 8]")
    asm_lines.append("    pxor mm0, mm2")
    asm_lines.append("    pxor mm1, mm3")
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
    """Generate x64 assembly to build string on stack."""
    if not string_data:
        return "", []

    size = len(string_data)
    asm_lines = []
    junk_used: list[str] = []
    junk_instructions = _JUNK_INSTRUCTIONS_X64

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
            asm_lines.append(_format_plain_stack_byte(i, b, "rsp"))
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )
    elif encoding == EncodingScheme.XOR_SINGLE:
        for i, b in enumerate(encoded_data):
            original = string_data[i]
            if original == 0:
                asm_lines.append(f"    mov byte [rsp+{i}], 0")
            else:
                asm_lines.append(f"    mov byte [rsp+{i}], 0x{b:02X}  ; XOR'd")
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )
        asm_lines.extend(_xor_single_decode_loop_x64(len(encoded_data), xor_key, id(encoded_data)))
    elif encoding == EncodingScheme.XOR_ROLLING:
        for i, b in enumerate(encoded_data):
            asm_lines.append(f"    mov byte [rsp+{i}], 0x{b:02X}")
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )
        asm_lines.extend(_xor_rolling_decode_loop_x64(len(encoded_data), xor_key, id(encoded_data)))
    elif encoding == EncodingScheme.ADD_SHIFT:
        for i, b in enumerate(encoded_data):
            asm_lines.append(f"    mov byte [rsp+{i}], 0x{b:02X}")
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )
        asm_lines.extend(_add_shift_decode_loop_x64(len(encoded_data), add_shift, id(encoded_data)))
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
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )

        aes_decode_lines = generate_aes_decode_asm_x64(aes_key, len(encoded_data), id(encoded_data))
        asm_lines.extend(aes_decode_lines)
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
    """Generate x86 (32-bit) assembly to build string on stack."""
    if not string_data:
        return "", []

    size = len(string_data)
    asm_lines = []
    junk_used: list[str] = []

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

    junk_instructions = _JUNK_INSTRUCTIONS_X86

    if encoding == EncodingScheme.PLAIN:
        for i, b in enumerate(string_data):
            asm_lines.append(_format_plain_stack_byte(i, b, "esp"))
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )
    elif encoding == EncodingScheme.XOR_SINGLE:
        for i, b in enumerate(encoded_data):
            asm_lines.append(f"    mov byte [esp+{i}], 0x{b:02X}")
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )
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
    elif encoding == EncodingScheme.XOR_ROLLING:
        for i, b in enumerate(encoded_data):
            asm_lines.append(f"    mov byte [esp+{i}], 0x{b:02X}")
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )
        decode_loop = [
            "    ; Decode rolling XOR string",
            "    lea edi, [esp]",
            f"    mov ecx, {len(encoded_data)}",
            f"    mov dl, 0x{xor_key:02X}",
            f".decode_loop_{id(encoded_data):x}:",
            "    xor byte [edi], dl",
            "    inc edi",
            "    imul dl, 7",
            "    inc dl",
            "    and dl, 0xFF",
            f"    loop .decode_loop_{id(encoded_data):x}",
        ]
        asm_lines.extend(decode_loop)
    elif encoding == EncodingScheme.ADD_SHIFT:
        for i, b in enumerate(encoded_data):
            asm_lines.append(f"    mov byte [esp+{i}], 0x{b:02X}")
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )
        decode_loop = [
            "    ; Decode ADD-shift'd string",
            "    lea edi, [esp]",
            f"    mov ecx, {len(encoded_data)}",
            f".decode_loop_{id(encoded_data):x}:",
            f"    sub byte [edi], {add_shift}",
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
            _append_optional_junk(
                asm_lines,
                junk_used,
                junk_instructions,
                interleave_junk=interleave_junk,
                junk_probability=junk_probability,
            )

        aes_decode_lines = generate_aes_decode_asm_x86(aes_key, len(encoded_data), id(encoded_data))
        asm_lines.extend(aes_decode_lines)

    return "\n".join(asm_lines), junk_used


def find_printable_strings(data: bytes, min_length: int = 4) -> list[tuple[int, bytes]]:
    """Find printable strings in binary data."""
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


__all__ = [
    "EncodingScheme",
    "find_printable_strings",
    "generate_aes_decode_asm_x64",
    "generate_aes_decode_asm_x86",
    "generate_stack_string_x64",
    "generate_stack_string_x86",
    "xor_bytes",
    "xor_rolling",
    "add_shift_encode",
    "_append_optional_junk",
    "_format_plain_stack_byte",
    "_xor_single_decode_loop_x64",
    "_xor_rolling_decode_loop_x64",
    "_add_shift_decode_loop_x64",
]
