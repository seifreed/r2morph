"""
Self-modifying code helper models and pure transformations.

This module owns the reusable data types, encryption helpers, stub
generators, and packing utilities used by
``r2morph.mutations.self_modifying_code``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum


class EncryptionScheme(Enum):
    """Available encryption schemes for self-modifying code."""

    XOR_ROLLING = "xor_rolling"
    XOR_KEY = "xor_key"
    ADD_SUB = "add_sub"
    ROL_ROR = "rol_ror"
    RC4 = "rc4"
    BLOWFISH = "blowfish"
    CUSTOM = "custom"


@dataclass
class EncryptedSection:
    """Represents an encrypted section of code."""

    address: int
    size: int
    original_bytes: bytes
    encrypted_bytes: bytes = field(default=b"")
    key: bytes = field(default=b"")
    scheme: EncryptionScheme = EncryptionScheme.XOR_KEY
    decrypt_stub_address: int = 0
    decrypt_stub_size: int = 0


@dataclass
class DecryptStub:
    """Represents a decryption stub."""

    address: int
    size: int
    code: bytes
    key_offset: int = 0
    data_offset: int = 0


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using XOR with key."""
    result = bytearray(len(data))
    key_len = len(key)
    for i, b in enumerate(data):
        result[i] = b ^ key[i % key_len]
    return bytes(result)


def xor_rolling_encrypt(data: bytes, initial_key: int) -> tuple[bytes, int]:
    """Encrypt data using rolling XOR."""
    result = bytearray(len(data))
    key = initial_key & 0xFF
    for i, b in enumerate(data):
        result[i] = b ^ key
        key = ((key * 7) + 1) & 0xFF
    return bytes(result), key


def add_sub_encrypt(data: bytes, key: int) -> bytes:
    """Encrypt data using addition/subtraction."""
    result = bytearray(len(data))
    k = key & 0xFF
    for i, b in enumerate(data):
        if i % 2 == 0:
            result[i] = (b + k) & 0xFF
        else:
            result[i] = (b - k) & 0xFF
    return bytes(result)


def rol_encrypt(data: bytes, shift: int) -> bytes:
    """Encrypt data using rotate left."""
    result = bytearray(len(data))
    s = shift & 7
    for i, b in enumerate(data):
        result[i] = ((b << s) | (b >> (8 - s))) & 0xFF
    return bytes(result)


def rc4_init(key: bytes) -> list:
    """Initialize RC4 S-box."""
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + key[i % len(key)]) & 0xFF
        s_box[i], s_box[j] = s_box[j], s_box[i]
    return s_box


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 encrypt/decrypt."""
    s_box = rc4_init(key)
    result = bytearray(len(data))
    i = j = 0
    for k, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s_box[i]) & 0xFF
        s_box[i], s_box[j] = s_box[j], s_box[i]
        result[k] = b ^ s_box[(s_box[i] + s_box[j]) & 0xFF]
    return bytes(result)


def generate_xor_decrypt_stub_x64(key: bytes, data_addr: int, data_size: int) -> bytes:
    """
    Generate x64 assembly for XOR decryption stub.

    Args:
        key: Encryption key
        data_addr: Address of encrypted data
        data_size: Size of encrypted data

    Returns:
        Machine code for decryption stub
    """
    stub_asm = f"""
    ; Polymorphic XOR decryption stub (x64)
    ; Key: {key.hex()}
    push rax
    push rcx
    push rsi
    push rdi

    lea rsi, [rip + encrypted_data]
    mov rcx, {data_size}
    mov rdi, rsi

.decrypt_loop:
    mov al, [rdi]
"""
    if len(key) <= 8:
        for k in key:
            stub_asm += f"    xor al, 0x{k:02X}\n"
    else:
        stub_asm += f"""
    ; Key is longer, use key table
    push rbx
    push rdx
    mov rdx, rcx
    lea rbx, [rip + key_table]
    and rdx, {len(key) - 1}
    xor al, [rbx + rdx]
    pop rdx
    pop rbx
"""

    stub_asm += """
    mov [rdi], al
    inc rdi
    loop .decrypt_loop
    pop rdi
    pop rsi
    pop rcx
    pop rax
    ret

encrypted_data:
"""
    return stub_asm.encode()


def generate_xor_decrypt_stub_x86(key: bytes, data_addr: int, data_size: int) -> bytes:
    """Generate x86 (32-bit) assembly for XOR decryption stub."""
    stub_asm = f"""
    ; Polymorphic XOR decryption stub (x86)
    push eax
    push ecx
    push esi
    push edi

    mov esi, encrypted_data
    mov ecx, {data_size}
    mov edi, esi

.decrypt_loop:
    mov al, [edi]
    xor al, 0x{key[0]:02X}
    mov [edi], al
    inc edi
    loop .decrypt_loop

    pop edi
    pop esi
    pop ecx
    pop eax
    ret

encrypted_data:
"""
    return stub_asm.encode()


def generate_polymorphic_stub_x64(key: bytes, data_size: int, seed: int | None = None) -> str:
    """
    Generate polymorphic decryption stub with random variations.

    The stub is regenerated each time with different instruction
    sequences that achieve the same result, making signature
    detection harder.

    Args:
        key: Encryption key
        data_size: Size of encrypted data
        seed: Optional random seed for reproducibility

    Returns:
        Assembly code string
    """
    if seed is not None:
        random.seed(seed)

    regs = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]
    random.shuffle(regs)
    ptr_reg = regs[0]
    cnt_reg = regs[1]
    tmp_reg = regs[2]

    prelude_junk = random.choice(
        [
            f"push {tmp_reg}\npop {tmp_reg}",
            f"xor {tmp_reg}, {tmp_reg}",
            "nop\nnop",
            "",
        ]
    )

    key_size = len(key)
    if key_size <= 8:
        key_load = "\n".join([f"mov {tmp_reg}, 0x" + key[::-1].hex() + "  ; key"])
    else:
        key_load = f"lea {tmp_reg}, [rip + key_table]"

    loop_variants = [
        f"""
.loop_start:
    xor byte [{ptr_reg}], {key[0]:02X}
    inc {ptr_reg}
    dec {cnt_reg}
    jnz .loop_start
""",
        f"""
.loop_start:
    mov al, [{ptr_reg}]
    xor al, {key[0]:02X}
    mov [{ptr_reg}], al
    inc {ptr_reg}
    dec {cnt_reg}
    jnz .loop_start
""",
        f"""
.loop_start:
    add byte [{ptr_reg}], {(-key[0]) & 0xFF:02X}
    sub byte [{ptr_reg}], {((-key[0]) + key[0]) & 0xFF:02X}
    xor byte [{ptr_reg}], {key[0]:02X}
    inc {ptr_reg}
    dec {cnt_reg}
    jnz .loop_start
""",
    ]

    loop_code = random.choice(loop_variants)

    stub = f"""
; Polymorphic decrypt stub (seed: {seed})
; Generated with random instruction variations

decrypt_entry:
    {prelude_junk}
    push {ptr_reg}
    push {cnt_reg}
    {key_load}
    lea {ptr_reg}, [rip + encrypted_data]
    mov {cnt_reg}, {data_size}
{loop_code}
    pop {cnt_reg}
    pop {ptr_reg}
    ret

encrypted_data:
"""
    return stub


def create_packed_binary(
    code: bytes, entry_point: int, arch: str = "x64", encryption: EncryptionScheme = EncryptionScheme.XOR_KEY
) -> tuple[bytes, bytes, bytes]:
    """
    Create a self-unpacking binary.

    Args:
        code: Code to pack
        entry_point: Entry point offset
        arch: Architecture
        encryption: Encryption scheme

    Returns:
        Tuple of (packed_binary, key, unpack_stub)
    """
    key = bytes(random.randint(0, 255) for _ in range(8))

    if encryption == EncryptionScheme.XOR_KEY:
        packed = xor_encrypt(code, key)
    elif encryption == EncryptionScheme.RC4:
        packed = rc4_crypt(code, key)
    else:
        packed = xor_encrypt(code, key)

    if arch == "x64":
        unpack_stub = generate_xor_decrypt_stub_x64(key, entry_point, len(packed))
    else:
        unpack_stub = generate_xor_decrypt_stub_x86(key, entry_point, len(packed))

    return packed, key, unpack_stub


def calculate_unpacking_offset(stub_size: int, alignment: int = 16) -> int:
    """Calculate offset for unpacked code after stub."""
    return (stub_size + alignment - 1) & ~(alignment - 1)


__all__ = [
    "DecryptStub",
    "EncryptedSection",
    "EncryptionScheme",
    "add_sub_encrypt",
    "calculate_unpacking_offset",
    "create_packed_binary",
    "generate_polymorphic_stub_x64",
    "generate_xor_decrypt_stub_x64",
    "generate_xor_decrypt_stub_x86",
    "rc4_crypt",
    "rc4_init",
    "rol_encrypt",
    "xor_encrypt",
    "xor_rolling_encrypt",
]
