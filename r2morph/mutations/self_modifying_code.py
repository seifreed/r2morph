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
from typing import Any

from r2morph.mutations.base import MutationPass
from r2morph.mutations.self_modifying_code_helpers import (
    DecryptStub,
    EncryptedSection,
    EncryptionScheme,
    add_sub_encrypt,
    calculate_unpacking_offset,
    create_packed_binary,
    generate_polymorphic_stub_x64,
    generate_xor_decrypt_stub_x64,
    generate_xor_decrypt_stub_x86,
    rc4_crypt,
    rc4_init,
    rol_encrypt,
    xor_encrypt,
    xor_rolling_encrypt,
)
from r2morph.relocations.cave_injector import CodeCaveInjector

logger = logging.getLogger(__name__)


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
        # encryption_scheme is documented as a string config option, but
        # the rest of the pass treats it as an EncryptionScheme enum
        # (e.g. .value, == comparisons). Coerce a string to the enum so a
        # JSON/dict config does not raise "'str' object has no attribute
        # 'value'"; fall back to the documented default for anything
        # unrecognised.
        scheme = self.config.get("encryption_scheme", EncryptionScheme.XOR_KEY)
        if not isinstance(scheme, EncryptionScheme):
            try:
                scheme = EncryptionScheme(scheme)
            except ValueError:
                scheme = EncryptionScheme.XOR_KEY
        self.encryption_scheme = scheme
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
            return generate_polymorphic_stub_x64(key, data_size, seed)
        if arch == "x64":
            return generate_xor_decrypt_stub_x64(key, data_addr, data_size).decode()
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
    ) -> bytes | None:
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
        if rel_offset < -2147483648 or rel_offset > 2147483647:
            logger.debug(f"Stub jmp rel32 out of range ({rel_offset}) for func 0x{func_addr:x}; skipping")
            return None
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

            # Build a provisional stub only to measure its size before a
            # cave is known. The size is constant regardless of cave_addr
            # (the final jmp is always a 5-byte rel32), so pass
            # cave_addr=func_addr: that keeps the provisional rel32 in
            # range (a dummy cave_addr=0 would make rel_offset ~= func_addr
            # and overflow int32 for any high-address binary).
            provisional_stub = self._build_xor_decrypt_stub(
                cave_addr=func_addr,
                func_addr=func_addr,
                func_size=func_size,
                key_byte=key_byte,
                saved_prologue=saved_prologue,
            )
            if provisional_stub is None:
                continue
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
            if stub_bytes is None:
                continue

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
            if jmp_rel < -2147483648 or jmp_rel > 2147483647:
                logger.debug(f"func->cave jmp rel32 out of range ({jmp_rel}) for func 0x{func_addr:x}; skipping")
                continue
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


__all__ = [
    "DecryptStub",
    "EncryptedSection",
    "EncryptionScheme",
    "SelfModifyingCodePass",
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
