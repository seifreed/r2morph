"""Regression tests for the StackStrings AES_256 keyed-XOR cipher.

Pre-fix bugs (both undetected because no test exercised AES_256):
  1. aes_encrypt_block indexed a 4-byte expanded key word as if it were
     a 16-byte round key -> IndexError for every input -> StackStrings
     AES_256 was dead.
  2. The emitted x64/x86 decode stubs only XOR'd the block with the
     first 16 key bytes once and never inverted the (broken) round
     cipher, so even without the crash the runtime string was garbage.

The fix makes encrypt/decrypt and both decode stubs the same involutive
keyed-XOR over keystream = key[0:16] ^ key[16:32]. These tests assert
round-trip, full-256-bit-key usage, and that the *generated asm text*
itself, decoded faithfully, recovers the plaintext. Real, no mocks.
"""

from __future__ import annotations

import re

from r2morph.crypto.aes import (
    aes_decrypt_block,
    aes_encrypt_block,
    aes_encrypt_string,
)
from r2morph.mutations.stack_strings import (
    generate_aes_decode_asm_x64,
    generate_aes_decode_asm_x86,
)

KEY = bytes(range(32))  # deterministic 32-byte key


def test_block_roundtrip_no_indexerror() -> None:
    for raw in (b"", b"A", b"sixteen bytes!!!", b"0123456789abcdefXYZ"):
        block = raw[:16].ljust(16, b"\x00")
        enc = aes_encrypt_block(block, KEY)
        assert len(enc) == 16
        assert aes_decrypt_block(enc, KEY) == block
        assert enc != block  # keystream is non-zero for this key


def test_encrypt_string_roundtrip_and_padding() -> None:
    for plain in (b"", b"x", b"secret", b"exactly sixteen!", b"seventeen bytes!!"):
        enc, k = aes_encrypt_string(plain, KEY)
        assert k == KEY
        assert len(enc) % 16 == 0
        padded = plain.ljust(len(enc), b"\x00")
        dec = b"".join(aes_decrypt_block(enc[i : i + 16], KEY) for i in range(0, len(enc), 16))
        assert dec == padded


def test_full_256_bit_key_influences_ciphertext() -> None:
    plain = b"the quick brown!"
    base, _ = aes_encrypt_string(plain, KEY)
    flipped = bytearray(KEY)
    flipped[20] ^= 0xFF  # a byte in the upper 128 bits (key[16:32])
    other, _ = aes_encrypt_string(plain, bytes(flipped))
    assert base != other  # upper key half must affect output


def _stack_key_from_asm(asm: list[str], width: int) -> bytes:
    """Reconstruct the 32 key bytes the stub writes onto the stack.

    width=8 (x64: ``mov r8,0x..``/``mov [rsp+i],r8``), width=4 (x86:
    ``eax``). Each immediate is ``key_chunk[::-1].hex()`` and the store
    is little-endian, so the bytes land back as the original key slice.
    """
    imm = re.compile(r"mov (?:r8|eax), 0x([0-9a-f]+)$")
    store = re.compile(r"mov \[(?:rsp|esp) \+ (\d+)\], (?:r8|eax)$")
    out = bytearray(32)
    pending: int | None = None
    for line in asm:
        s = line.strip()
        m = imm.search(s)
        if m:
            pending = int(m.group(1), 16)
            continue
        m = store.search(s)
        if m and pending is not None:
            off = int(m.group(1))
            out[off : off + width] = pending.to_bytes(width, "big")[::-1]
            pending = None
    return bytes(out)


def _decode_with_emitted_keystream(asm: list[str], cipher: bytes, width: int) -> bytes:
    key = _stack_key_from_asm(asm, width)
    keystream = bytes(key[i] ^ key[i + 16] for i in range(16))
    return bytes(cipher[i] ^ keystream[i % 16] for i in range(len(cipher)))


def test_emitted_x64_decode_inverts_encoder() -> None:
    for plain in (b"hi", b"a longer secret string here", b"exactly sixteen!"):
        enc, k = aes_encrypt_string(plain, KEY)
        asm = generate_aes_decode_asm_x64(k, len(enc), 0xABCD)
        joined = "\n".join(asm)
        assert "movdqu xmm1, [rsp]" in joined
        assert "movdqu xmm2, [rsp + 16]" in joined
        assert "pxor xmm1, xmm2" in joined
        assert "pxor xmm0, xmm1" in joined
        assert _decode_with_emitted_keystream(asm, enc, 8) == plain.ljust(len(enc), b"\x00")


def test_emitted_x86_decode_inverts_encoder() -> None:
    for plain in (b"hi", b"a longer secret string here", b"exactly sixteen!"):
        enc, k = aes_encrypt_string(plain, KEY)
        asm = generate_aes_decode_asm_x86(k, len(enc), 0xABCD)
        joined = "\n".join(asm)
        assert "movq mm2, [esp]" in joined
        assert "pxor mm2, [esp + 16]" in joined
        assert "movq mm3, [esp + 8]" in joined
        assert "pxor mm3, [esp + 24]" in joined
        assert _decode_with_emitted_keystream(asm, enc, 4) == plain.ljust(len(enc), b"\x00")
