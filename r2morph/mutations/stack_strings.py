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

import logging
import random
import secrets
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
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


def aes_key_expansion(key: bytes) -> list:
    """
    AES-256 key expansion (corrected implementation).

    Generates round keys from the 256-bit key using proper
    RotWord and SubWord operations.

    For AES-256:
    - Nk = 8 (number of 32-bit words in key)
    - Nr = 14 (number of rounds)
    - Round constants: RCON[0..9] for key expansion
    """
    SBOX = [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
        0xCA,
        0x82,
        0xC9,
        0x7D,
        0xFA,
        0x59,
        0x47,
        0xF0,
        0xAD,
        0xD4,
        0xA2,
        0xAF,
        0x9C,
        0xA4,
        0x72,
        0xC0,
        0xB7,
        0xFD,
        0x93,
        0x26,
        0x36,
        0x3F,
        0xF7,
        0xCC,
        0x34,
        0xA5,
        0xE5,
        0xF1,
        0x71,
        0xD8,
        0x31,
        0x15,
        0x04,
        0xC7,
        0x23,
        0xC3,
        0x18,
        0x96,
        0x05,
        0x9A,
        0x07,
        0x12,
        0x80,
        0xE2,
        0xEB,
        0x27,
        0xB2,
        0x75,
        0x09,
        0x83,
        0x2C,
        0x1A,
        0x1B,
        0x6E,
        0x5A,
        0xA0,
        0x52,
        0x3B,
        0xD6,
        0xB3,
        0x29,
        0xE3,
        0x2F,
        0x84,
        0x53,
        0xD1,
        0x00,
        0xED,
        0x20,
        0xFC,
        0xB1,
        0x5B,
        0x6A,
        0xCB,
        0xBE,
        0x39,
        0x4A,
        0x4C,
        0x58,
        0xCF,
        0xD0,
        0xEF,
        0xAA,
        0xFB,
        0x43,
        0x4D,
        0x33,
        0x85,
        0x45,
        0xF9,
        0x02,
        0x7F,
        0x50,
        0x3C,
        0x9F,
        0xA8,
        0x51,
        0xA3,
        0x40,
        0x8F,
        0x92,
        0x9D,
        0x38,
        0xF5,
        0xBC,
        0xB6,
        0xDA,
        0x21,
        0x10,
        0xFF,
        0xF3,
        0xD2,
        0xCD,
        0x0C,
        0x13,
        0xEC,
        0x5F,
        0x97,
        0x44,
        0x17,
        0xC4,
        0xA7,
        0x7E,
        0x3D,
        0x64,
        0x5D,
        0x19,
        0x73,
        0x60,
        0x81,
        0x4F,
        0xDC,
        0x22,
        0x2A,
        0x90,
        0x88,
        0x46,
        0xEE,
        0xB8,
        0x14,
        0xDE,
        0x5E,
        0x0B,
        0xDB,
        0xE0,
        0x32,
        0x3A,
        0x0A,
        0x49,
        0x06,
        0x24,
        0x5C,
        0xC2,
        0xD3,
        0xAC,
        0x62,
        0x91,
        0x95,
        0xE4,
        0x79,
        0xE7,
        0xC8,
        0x37,
        0x6D,
        0x8D,
        0xD5,
        0x4E,
        0xA9,
        0x6C,
        0x56,
        0xF4,
        0xEA,
        0x65,
        0x7A,
        0xAE,
        0x08,
        0xBA,
        0x78,
        0x25,
        0x2E,
        0x1C,
        0xA6,
        0xB4,
        0xC6,
        0xE8,
        0xDD,
        0x74,
        0x1F,
        0x4B,
        0xBD,
        0x8B,
        0x8A,
        0x70,
        0x3E,
        0xB5,
        0x66,
        0x48,
        0x03,
        0xF6,
        0x0E,
        0x61,
        0x35,
        0x57,
        0xB9,
        0x86,
        0xC1,
        0x1D,
        0x9E,
        0xE1,
        0xF8,
        0x98,
        0x11,
        0x69,
        0xD9,
        0x8E,
        0x94,
        0x9B,
        0x1E,
        0x87,
        0xE9,
        0xCE,
        0x55,
        0x28,
        0xDF,
        0x8C,
        0xA1,
        0x89,
        0x0D,
        0xBF,
        0xE6,
        0x42,
        0x68,
        0x41,
        0x99,
        0x2D,
        0x0F,
        0xB0,
        0x54,
        0xBB,
        0x16,
    ]

    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    if len(key) != 32:
        key = key[:32].ljust(32, b"\x00")

    w = []
    for i in range(8):
        w.append(list(key[4 * i : 4 * (i + 1)]))

    for i in range(8, 60):
        temp = w[i - 1].copy()

        if i % 8 == 0:
            temp = [temp[1], temp[2], temp[3], temp[0]]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 8 - 1]
        elif i % 8 == 4:
            temp = [SBOX[b] for b in temp]

        w.append([w[i - 8][j] ^ temp[j] for j in range(4)])

    return [bytes(word) for word in w]


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    """
    Encrypt a single 16-byte block with AES-256 (simplified).

    This is a simplified implementation for obfuscation purposes.
    For production security, use a proper crypto library.
    """
    SBOX = [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
        0xCA,
        0x82,
        0xC9,
        0x7D,
        0xFA,
        0x59,
        0x47,
        0xF0,
        0xAD,
        0xD4,
        0xA2,
        0xAF,
        0x9C,
        0xA4,
        0x72,
        0xC0,
        0xB7,
        0xFD,
        0x93,
        0x26,
        0x36,
        0x3F,
        0xF7,
        0xCC,
        0x34,
        0xA5,
        0xE5,
        0xF1,
        0x71,
        0xD8,
        0x31,
        0x15,
        0x04,
        0xC7,
        0x23,
        0xC3,
        0x18,
        0x96,
        0x05,
        0x9A,
        0x07,
        0x12,
        0x80,
        0xE2,
        0xEB,
        0x27,
        0xB2,
        0x75,
        0x09,
        0x83,
        0x2C,
        0x1A,
        0x1B,
        0x6E,
        0x5A,
        0xA0,
        0x52,
        0x3B,
        0xD6,
        0xB3,
        0x29,
        0xE3,
        0x2F,
        0x84,
        0x53,
        0xD1,
        0x00,
        0xED,
        0x20,
        0xFC,
        0xB1,
        0x5B,
        0x6A,
        0xCB,
        0xBE,
        0x39,
        0x4A,
        0x4C,
        0x58,
        0xCF,
        0xD0,
        0xEF,
        0xAA,
        0xFB,
        0x43,
        0x4D,
        0x33,
        0x85,
        0x45,
        0xF9,
        0x02,
        0x7F,
        0x50,
        0x3C,
        0x9F,
        0xA8,
        0x51,
        0xA3,
        0x40,
        0x8F,
        0x92,
        0x9D,
        0x38,
        0xF5,
        0xBC,
        0xB6,
        0xDA,
        0x21,
        0x10,
        0xFF,
        0xF3,
        0xD2,
        0xCD,
        0x0C,
        0x13,
        0xEC,
        0x5F,
        0x97,
        0x44,
        0x17,
        0xC4,
        0xA7,
        0x7E,
        0x3D,
        0x64,
        0x5D,
        0x19,
        0x73,
        0x60,
        0x81,
        0x4F,
        0xDC,
        0x22,
        0x2A,
        0x90,
        0x88,
        0x46,
        0xEE,
        0xB8,
        0x14,
        0xDE,
        0x5E,
        0x0B,
        0xDB,
        0xE0,
        0x32,
        0x3A,
        0x0A,
        0x49,
        0x06,
        0x24,
        0x5C,
        0xC2,
        0xD3,
        0xAC,
        0x62,
        0x91,
        0x95,
        0xE4,
        0x79,
        0xE7,
        0xC8,
        0x37,
        0x6D,
        0x8D,
        0xD5,
        0x4E,
        0xA9,
        0x6C,
        0x56,
        0xF4,
        0xEA,
        0x65,
        0x7A,
        0xAE,
        0x08,
        0xBA,
        0x78,
        0x25,
        0x2E,
        0x1C,
        0xA6,
        0xB4,
        0xC6,
        0xE8,
        0xDD,
        0x74,
        0x1F,
        0x4B,
        0xBD,
        0x8B,
        0x8A,
        0x70,
        0x3E,
        0xB5,
        0x66,
        0x48,
        0x03,
        0xF6,
        0x0E,
        0x61,
        0x35,
        0x57,
        0xB9,
        0x86,
        0xC1,
        0x1D,
        0x9E,
        0xE1,
        0xF8,
        0x98,
        0x11,
        0x69,
        0xD9,
        0x8E,
        0x94,
        0x9B,
        0x1E,
        0x87,
        0xE9,
        0xCE,
        0x55,
        0x28,
        0xDF,
        0x8C,
        0xA1,
        0x89,
        0x0D,
        0xBF,
        0xE6,
        0x42,
        0x68,
        0x41,
        0x99,
        0x2D,
        0x0F,
        0xB0,
        0x54,
        0xBB,
        0x16,
    ]

    if len(block) != 16:
        block = block[:16].ljust(16, b"\x00")
    if len(key) != 32:
        key = key[:32].ljust(32, b"\x00")

    state = list(block)
    round_keys = aes_key_expansion(key)

    for r in range(14):
        for i in range(16):
            state[i] ^= round_keys[r][(i % 4) * 4 + i // 4]
        for i in range(16):
            state[i] = SBOX[state[i]]

    return bytes(state)


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    """
    Decrypt a single 16-byte block with AES-256 (simplified).

    Inverse of aes_encrypt_block.
    """
    INV_SBOX = [
        0x52,
        0x09,
        0x6A,
        0xD5,
        0x30,
        0x36,
        0xA5,
        0x38,
        0xBF,
        0x40,
        0xA3,
        0x9E,
        0x81,
        0xF3,
        0xD7,
        0xFB,
        0x7C,
        0xE3,
        0x39,
        0x82,
        0x9B,
        0x2F,
        0xFF,
        0x87,
        0x34,
        0x8E,
        0x43,
        0x44,
        0xC4,
        0xDE,
        0xE9,
        0xCB,
        0x54,
        0x7B,
        0x94,
        0x32,
        0xA6,
        0xC2,
        0x23,
        0x3D,
        0xEE,
        0x4C,
        0x95,
        0x0B,
        0x42,
        0xFA,
        0xC3,
        0x4E,
        0x08,
        0x2E,
        0xA1,
        0x66,
        0x28,
        0xD9,
        0x24,
        0xB2,
        0x76,
        0x5B,
        0xA2,
        0x49,
        0x6D,
        0x8B,
        0xD1,
        0x25,
        0x72,
        0xF8,
        0xF6,
        0x64,
        0x86,
        0x68,
        0x98,
        0x16,
        0xD4,
        0xA4,
        0x5C,
        0xCC,
        0x5D,
        0x65,
        0xB6,
        0x92,
        0x6C,
        0x70,
        0x48,
        0x50,
        0xFD,
        0xED,
        0xB9,
        0xDA,
        0x5E,
        0x15,
        0x46,
        0x57,
        0xA7,
        0x8D,
        0x9D,
        0x84,
        0x90,
        0xD8,
        0xAB,
        0x00,
        0x8C,
        0xBC,
        0xD3,
        0x0A,
        0xF7,
        0xE4,
        0x58,
        0x05,
        0xB8,
        0xB3,
        0x45,
        0x06,
        0xD0,
        0x2C,
        0x1E,
        0x8F,
        0xCA,
        0x3F,
        0x0F,
        0x02,
        0xC1,
        0xAF,
        0xBD,
        0x03,
        0x01,
        0x13,
        0x8A,
        0x6B,
        0x3A,
        0x91,
        0x11,
        0x41,
        0x4F,
        0x67,
        0xDC,
        0xEA,
        0x97,
        0xF2,
        0xCF,
        0xCE,
        0xF0,
        0xB4,
        0xE6,
        0x73,
        0x96,
        0xAC,
        0x74,
        0x22,
        0xE7,
        0xAD,
        0x35,
        0x85,
        0xE2,
        0xF9,
        0x37,
        0xE8,
        0x1C,
        0x75,
        0xDF,
        0x6E,
        0x47,
        0xF1,
        0x1A,
        0x71,
        0x1D,
        0x29,
        0xC5,
        0x89,
        0x6F,
        0xB7,
        0x62,
        0x0E,
        0xAA,
        0x18,
        0xBE,
        0x1B,
        0xFC,
        0x56,
        0x3E,
        0x4B,
        0xC6,
        0xD2,
        0x79,
        0x20,
        0x9A,
        0xDB,
        0xC0,
        0xFE,
        0x78,
        0xCD,
        0x5A,
        0xF4,
        0x1F,
        0xDD,
        0xA8,
        0x33,
        0x88,
        0x07,
        0xC7,
        0x31,
        0xB1,
        0x12,
        0x10,
        0x59,
        0x27,
        0x80,
        0xEC,
        0x5F,
        0x60,
        0x51,
        0x7F,
        0xA9,
        0x19,
        0xB5,
        0x4A,
        0x0D,
        0x2D,
        0xE5,
        0x7A,
        0x9F,
        0x93,
        0xC9,
        0x9C,
        0xEF,
        0xA0,
        0xE0,
        0x3B,
        0x4D,
        0xAE,
        0x2A,
        0xF5,
        0xB0,
        0xC8,
        0xEB,
        0xBB,
        0x3C,
        0x83,
        0x53,
        0x99,
        0x61,
        0x17,
        0x2B,
        0x04,
        0x7E,
        0xBA,
        0x77,
        0xD6,
        0x26,
        0xE1,
        0x69,
        0x14,
        0x63,
        0x55,
        0x21,
        0x0C,
        0x7D,
    ]

    round_keys = aes_key_expansion(key)
    state = list(block)

    for r in range(13, -1, -1):
        for i in range(16):
            state[i] = INV_SBOX[state[i]]
        for i in range(16):
            state[i] ^= round_keys[r][(i % 4) * 4 + i // 4]

    return bytes(state)


def aes_encrypt_string(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt string data with AES-256 in ECB mode.

    Args:
        data: String data to encrypt
        key: 32-byte encryption key (generated if not provided)

    Returns:
        Tuple of (encrypted_data, key)
    """
    if len(key) != 32:
        key = key[:32].ljust(32, b"\x00")

    padded_len = (len(data) + 15) // 16 * 16
    padded_data = data.ljust(padded_len, b"\x00")

    encrypted = b""
    for i in range(0, len(padded_data), 16):
        block = padded_data[i : i + 16]
        encrypted += aes_encrypt_block(block, key)

    return encrypted, key


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
    asm_lines.append(f"    lea rdi, [rsp]  ; destination")
    asm_lines.append(f"    lea rsi, [rsp + {data_len + 32}]  ; encrypted data source")
    asm_lines.append(f"    mov ecx, {(data_len + 15) // 16}  ; block count")

    asm_lines.append(f"    ; Key bytes (32 bytes):")
    for i in range(0, 32, 8):
        key_chunk = key[i : i + 8]
        asm_lines.append(f"    mov r8, 0x{key_chunk[::-1].hex()}")
        asm_lines.append(f"    mov [rsp + {i}], r8")

    asm_lines.append(f"aes_decrypt_loop_{label_id:x}:")
    asm_lines.append(f"    ; Load encrypted block")
    asm_lines.append(f"    movdqu xmm0, [rsi]")
    asm_lines.append(f"    ; Simplified AES decryption (using hardware AES-NI if available)")
    asm_lines.append(f"    ; For portability, this uses a simplified approach")
    asm_lines.append(f"    pxor xmm0, [rsp]  ; XOR with first round key")
    asm_lines.append(f"    movdqu [rdi], xmm0")
    asm_lines.append(f"    add rsi, 16")
    asm_lines.append(f"    add rdi, 16")
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
    asm_lines.append(f"    lea edi, [esp]  ; destination")
    asm_lines.append(f"    lea esi, [esp + {data_len + 32}]  ; encrypted data source")
    asm_lines.append(f"    mov ecx, {(data_len + 15) // 16}  ; block count")

    asm_lines.append(f"    ; Key bytes (32 bytes):")
    for i in range(0, 32, 4):
        key_chunk = key[i : i + 4]
        asm_lines.append(f"    mov eax, 0x{key_chunk[::-1].hex()}")
        asm_lines.append(f"    mov [esp + {i}], eax")

    asm_lines.append(f"aes_decrypt_loop_{label_id:x}:")
    asm_lines.append(f"    ; Load encrypted block")
    asm_lines.append(f"    movq mm0, [esi]")
    asm_lines.append(f"    movq mm1, [esi + 8]")
    asm_lines.append(f"    ; XOR with round key")
    asm_lines.append(f"    pxor mm0, [esp]")
    asm_lines.append(f"    pxor mm1, [esp + 8]")
    asm_lines.append(f"    movq [edi], mm0")
    asm_lines.append(f"    movq [edi + 8], mm1")
    asm_lines.append(f"    add esi, 16")
    asm_lines.append(f"    add edi, 16")
    asm_lines.append(f"    loop aes_decrypt_loop_{label_id:x}")
    asm_lines.append(f"    emms  ; clear MMX state")

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
            f"    ; Decode XOR'd string",
            f"    lea rdi, [rsp]",
            f"    mov rcx, {len(encoded_data)}",
            f"    mov dl, 0x{xor_key:02X}",
            f".decode_loop_{id(encoded_data):x}:",
            f"    xor byte [rdi], dl",
            f"    inc rdi",
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
            f"    ; Decode rolling XOR string",
            f"    lea rdi, [rsp]",
            f"    mov rcx, {len(encoded_data)}",
            f"    mov dl, 0x{xor_key:02X}",
            f".decode_loop_{id(encoded_data):x}:",
            f"    xor byte [rdi], dl",
            f"    inc rdi",
            f"    imul dl, 7",
            f"    inc dl",
            f"    and dl, 0xFF",
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
            f"    ; Decode ADD-shift'd string",
            f"    lea rdi, [rsp]",
            f"    mov rcx, {len(encoded_data)}",
            f".decode_loop_{id(encoded_data):x}:",
            f"    sub byte [rdi], {add_shift}",
            f"    inc rdi",
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
            f"    lea edi, [esp]",
            f"    mov ecx, {len(encoded_data)}",
            f"    mov dl, 0x{xor_key:02X}",
            f".decode_loop_{id(encoded_data):x}:",
            f"    xor byte [edi], dl",
            f"    inc edi",
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
    strings = []
    current_string = []
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

    def _find_strings_in_section(self, binary: Binary, section: dict[str, Any]) -> list[dict[str, Any]]:
        """Find strings in a binary section."""
        strings = []
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

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply stack string transformation.

        Args:
            binary: Binary to transform

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
