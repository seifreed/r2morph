"""
Self-Modifying Code - Runtime code decryption and modification.

Implements techniques for code that modifies itself at runtime:
- Code encryption/decryption at execution time
- Polymorphic decryption stubs
- Self-unpacking code sections
- Dynamic code generation

This is a key technique in metamorphic malware where the code
decrypts itself before execution, making static analysis difficult.

Example transformation:

    Original:
        mov eax, 1
        add eax, 5
        ret

    Encrypted (stored):
        db 0xE8, 0x3D, 0x72, 0x19, 0xA5  ; encrypted bytes
        db 0xC2, 0x8B, 0x44, 0xF1, 0x03

    Runtime:
        call decrypt_stub
        ; decrypted code executes
        mov eax, 1
        add eax, 5
        ret

The decrypt_stub is polymorphic and regenerated each time.
"""

from __future__ import annotations

import logging
import random
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from r2morph.mutations.base import MutationPass

if TYPE_CHECKING:
    from r2morph.protocols import BinaryAccessProtocol

logger = logging.getLogger(__name__)


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
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 encrypt/decrypt."""
    S = rc4_init(key)
    result = bytearray(len(data))
    i = j = 0
    for k, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        result[k] = b ^ S[(S[i] + S[j]) & 0xFF]
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
            f"nop\nnop",
            "",
        ]
    )

    key_size = len(key)
    if key_size <= 8:
        key_load = "\n".join([f"mov {tmp_reg}, 0x" + key[::-1].hex() + f"  ; key"])
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


class SelfModifyingCodePass(MutationPass):
    """
    Mutation pass that creates self-modifying code.

    Encrypts code sections and generates polymorphic decryption
    stubs that run before the actual code executes.

    Config options:
        - probability: Probability of encrypting each function (default: 0.3)
        - max_functions: Maximum functions to encrypt (default: 10)
        - encryption_scheme: Encryption algorithm to use (default: "xor_key")
        - polymorphic: Generate polymorphic stubs (default: True)
        - key_size: Size of encryption key in bytes (default: 8)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="SelfModifyingCode", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 10)
        self.encryption_scheme = self.config.get("encryption_scheme", EncryptionScheme.XOR_KEY)
        self.polymorphic = self.config.get("polymorphic", True)
        self.key_size = self.config.get("key_size", 8)
        self.set_support(
            formats=("ELF", "PE", "Mach-O"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "encrypts code sections at rest",
                "generates polymorphic decrypt stubs",
                "runtime decryption before execution",
            ),
        )

    def _generate_key(self, size: int | None = None) -> bytes:
        """Generate random encryption key."""
        if size is None:
            size = self.key_size
        return bytes(random.randint(0, 255) for _ in range(size))

    def _encrypt_data(self, data: bytes, key: bytes, scheme: EncryptionScheme) -> bytes:
        """Encrypt data using the specified scheme."""
        if scheme == EncryptionScheme.XOR_KEY:
            return xor_encrypt(data, key)
        elif scheme == EncryptionScheme.XOR_ROLLING:
            result, _ = xor_rolling_encrypt(data, key[0])
            return result
        elif scheme == EncryptionScheme.ADD_SUB:
            return add_sub_encrypt(data, key[0])
        elif scheme == EncryptionScheme.ROL_ROR:
            return rol_encrypt(data, key[0])
        elif scheme == EncryptionScheme.RC4:
            return rc4_crypt(data, key)
        else:
            return xor_encrypt(data, key)

    def _generate_decrypt_stub(self, key: bytes, data_addr: int, data_size: int, arch: str = "x64") -> str:
        """Generate decryption stub assembly."""
        if self.polymorphic:
            seed = random.randint(0, 0xFFFFFFFF)
            if arch == "x64":
                return generate_polymorphic_stub_x64(key, data_size, seed)
            else:
                return generate_polymorphic_stub_x64(key, data_size, seed)
        else:
            if arch == "x64":
                return generate_xor_decrypt_stub_x64(key, data_addr, data_size).decode()
            else:
                return generate_xor_decrypt_stub_x86(key, data_addr, data_size).decode()

    def _find_encryptable_functions(self, binary: Any) -> list[dict[str, Any]]:
        """Find functions suitable for encryption."""
        encryptable = []
        functions = binary.get_functions()

        for func in functions:
            if func.get("size", 0) < 16:
                continue

            flags = func.get("flags", [])
            if "sym.main" in flags or "entry" in str(flags):
                continue

            encryptable.append(func)

        return encryptable

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply self-modifying code transformation.

        Args:
            binary: Any to transform

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying self-modifying code transformation")

        encryptable = self._find_encryptable_functions(binary)
        encrypted_count = 0
        total_size = 0
        stub_sizes = []

        for func in encryptable:
            if encrypted_count >= self.max_functions:
                break

            if random.random() > self.probability:
                continue

            func_addr = func.get("addr", 0)
            func_size = func.get("size", 0)

            if func_size < 16:
                continue

            key = self._generate_key()

            try:
                original_bytes = binary.read_bytes(func_addr, func_size)
            except Exception as e:
                logger.debug(f"Could not read function at 0x{func_addr:x}: {e}")
                continue

            arch_info = binary.get_arch_info()
            arch = "x64" if arch_info.get("arch") in ("x86_64", "x64", "amd64") else "x86"
            encrypted = self._encrypt_data(original_bytes, key, self.encryption_scheme)

            stub_code = self._generate_decrypt_stub(key, func_addr, func_size, arch)

            encrypted_count += 1
            total_size += func_size
            stub_sizes.append(len(stub_code))

            logger.debug(
                f"Encrypted function at 0x{func_addr:x}: {func_size} bytes, scheme={self.encryption_scheme.value}"
            )

        return {
            "functions_encrypted": encrypted_count,
            "total_bytes_encrypted": total_size,
            "encryption_scheme": self.encryption_scheme.value,
            "key_size": self.key_size,
            "polymorphic": self.polymorphic,
            "average_stub_size": sum(stub_sizes) / max(len(stub_sizes), 1),
        }


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
