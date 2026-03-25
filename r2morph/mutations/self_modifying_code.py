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
from r2morph.relocations.cave_injector import CodeCaveInjector

if TYPE_CHECKING:
    pass

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

    def _build_xor_decrypt_stub(
        self,
        cave_addr: int,
        func_addr: int,
        func_size: int,
        key_byte: int,
        saved_prologue: bytes,
    ) -> bytes:
        """
        Build a raw x86_64 XOR decryption stub.

        The stub performs the following at runtime:
        1. Save registers (rbx, rcx, rsi)
        2. mprotect the target page to RWX
        3. Restore the original 5-byte prologue at func_addr
        4. XOR-decrypt func_addr+5 through func_addr+func_size
        5. Restore registers
        6. Jump to func_addr (now fully decrypted)

        Args:
            cave_addr: Address where this stub will be placed
            func_addr: Address of the encrypted function
            func_size: Total size of the function
            key_byte: Single-byte XOR key
            saved_prologue: Original 5 bytes from func_addr (before jmp overwrite)

        Returns:
            Raw machine code bytes for the stub
        """
        page_size = 0x1000
        page_addr = func_addr & ~(page_size - 1)
        # Cover the case where the function spans a page boundary
        pages_needed = ((func_addr + func_size - page_addr) + page_size - 1) // page_size
        mprotect_size = pages_needed * page_size

        decrypt_start = func_addr + 5
        decrypt_size = func_size - 5

        stub = bytearray()

        # --- Save registers ---
        stub += b"\x53"  # push rbx
        stub += b"\x51"  # push rcx
        stub += b"\x56"  # push rsi

        # --- mprotect syscall: make target page RWX ---
        # mov rdi, page_addr (movabs rdi, imm64)
        stub += b"\x48\xbf" + struct.pack("<Q", page_addr)
        # mov rsi, mprotect_size (movabs rsi, imm64)
        stub += b"\x48\xbe" + struct.pack("<Q", mprotect_size)
        # mov edx, 7 (PROT_READ | PROT_WRITE | PROT_EXEC)
        stub += b"\xba" + struct.pack("<I", 7)
        # mov eax, 10 (SYS_mprotect)
        stub += b"\xb8" + struct.pack("<I", 10)
        # syscall
        stub += b"\x0f\x05"

        # --- Restore original 5-byte prologue at func_addr ---
        # mov rsi, func_addr
        stub += b"\x48\xbe" + struct.pack("<Q", func_addr)
        for i, byte_val in enumerate(saved_prologue):
            # mov byte [rsi + i], byte_val
            stub += b"\xc6\x46" + struct.pack("b", i) + struct.pack("B", byte_val)

        # --- XOR decrypt loop over func_addr+5 .. func_addr+func_size ---
        if decrypt_size > 0:
            # lea rsi, [func_addr + 5]  => mov rsi, imm64
            stub += b"\x48\xbe" + struct.pack("<Q", decrypt_start)
            # mov ecx, decrypt_size
            stub += b"\xb9" + struct.pack("<I", decrypt_size)
            # XOR loop:
            # .loop:
            #   xor byte [rsi], key_byte   ; 80 36 <key>
            #   inc rsi                     ; 48 ff c6
            #   dec ecx                     ; ff c9
            #   jnz .loop                   ; 75 f6 (-10)
            loop_body = (
                b"\x80\x36"
                + struct.pack("B", key_byte)  # xor byte [rsi], key
                + b"\x48\xff\xc6"  # inc rsi
                + b"\xff\xc9"  # dec ecx
            )
            jnz_offset = -(len(loop_body) + 2)  # +2 for jnz itself
            loop_body += b"\x75" + struct.pack("b", jnz_offset)
            stub += loop_body

        # --- Restore registers ---
        stub += b"\x5e"  # pop rsi
        stub += b"\x59"  # pop rcx
        stub += b"\x5b"  # pop rbx

        # --- Jump to original function (now decrypted) ---
        jmp_target = func_addr
        # Offset is relative to the address after the jmp instruction
        jmp_from = cave_addr + len(stub) + 5  # 5 = size of jmp rel32
        rel_offset = jmp_target - jmp_from
        stub += b"\xe9" + struct.pack("<i", rel_offset)

        return bytes(stub)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply self-modifying code transformation.

        Encrypts selected functions in-place with XOR, writes a decryption
        stub into a code cave, and patches the function entry to jump to
        the stub. At runtime, the stub decrypts the function and transfers
        control to it.

        Args:
            binary: Binary to transform

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying self-modifying code transformation")

        injector = CodeCaveInjector(binary)
        encryptable = self._find_encryptable_functions(binary)
        encrypted_count = 0
        total_size = 0
        stub_sizes: list[int] = []

        for func in encryptable:
            if encrypted_count >= self.max_functions:
                break

            if random.random() > self.probability:
                continue

            func_addr = func.get("addr", 0)
            func_size = func.get("size", 0)

            if func_size < 16:
                continue

            key = self._generate_key(size=1)
            key_byte = key[0]

            try:
                original_bytes = binary.read_bytes(func_addr, func_size)
            except Exception as e:
                logger.debug(f"Could not read function at 0x{func_addr:x}: {e}")
                continue

            if not original_bytes or len(original_bytes) < 5:
                continue

            # Save the first 5 bytes (will be overwritten by the jmp)
            saved_prologue = original_bytes[:5]

            # Encrypt everything after the first 5 bytes
            body_bytes = original_bytes[5:]
            encrypted_body = self._encrypt_data(body_bytes, key, EncryptionScheme.XOR_KEY)

            # Build the raw decryption stub (needs cave_addr, estimated first)
            # We need to know stub size to find a cave, but stub size depends
            # on cave_addr for the final jmp offset. Build a provisional stub
            # with a dummy cave_addr to measure its size (the size is constant
            # regardless of cave_addr because all immediates are 64-bit).
            provisional_stub = self._build_xor_decrypt_stub(
                cave_addr=0,
                func_addr=func_addr,
                func_size=func_size,
                key_byte=key_byte,
                saved_prologue=saved_prologue,
            )
            stub_size = len(provisional_stub)

            # Find a code cave for the stub
            cave = injector.find_cave_for_code(stub_size, require_executable=True)
            if cave is None:
                logger.debug(f"No code cave ({stub_size} bytes) for function at 0x{func_addr:x}")
                continue

            cave_addr = cave.address

            # Rebuild stub with the real cave_addr (updates the final jmp offset)
            stub_bytes = self._build_xor_decrypt_stub(
                cave_addr=cave_addr,
                func_addr=func_addr,
                func_size=func_size,
                key_byte=key_byte,
                saved_prologue=saved_prologue,
            )

            # 1. Write the decryption stub into the cave
            if not binary.write_bytes(cave_addr, stub_bytes):
                logger.debug(f"Failed to write stub at cave 0x{cave_addr:x}")
                continue

            # 2. Write encrypted body over original function bytes (after first 5)
            if not binary.write_bytes(func_addr + 5, encrypted_body):
                logger.debug(f"Failed to write encrypted body at 0x{func_addr + 5:x}")
                continue

            # 3. Write a 5-byte jmp from func_addr to the stub
            jmp_rel = cave_addr - (func_addr + 5)
            jmp_bytes = b"\xe9" + struct.pack("<i", jmp_rel)
            if not binary.write_bytes(func_addr, jmp_bytes):
                logger.debug(f"Failed to write jmp at 0x{func_addr:x}")
                continue

            # Record the mutation
            self._record_mutation(
                function_address=func_addr,
                start_address=func_addr,
                end_address=func_addr + func_size - 1,
                original_bytes=original_bytes,
                mutated_bytes=jmp_bytes + encrypted_body,
                original_disasm=f"function ({func_size} bytes)",
                mutated_disasm=f"encrypted+stub ({func_size} bytes, cave@0x{cave_addr:x})",
                mutation_kind="self_modifying_code",
                metadata={
                    "cave_address": cave_addr,
                    "stub_size": len(stub_bytes),
                    "key": key.hex(),
                    "encryption_scheme": EncryptionScheme.XOR_KEY.value,
                },
            )

            encrypted_count += 1
            total_size += func_size
            stub_sizes.append(len(stub_bytes))

            logger.debug(
                f"Encrypted function at 0x{func_addr:x}: {func_size} bytes, "
                f"stub at 0x{cave_addr:x} ({len(stub_bytes)} bytes)"
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
