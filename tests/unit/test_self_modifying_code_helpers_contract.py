"""Contract tests for the self-modifying code helper module."""

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
    xor_encrypt,
    xor_rolling_encrypt,
)


def test_models_and_enum_are_available() -> None:
    section = EncryptedSection(
        address=0x1000,
        size=32,
        original_bytes=b"\x90" * 32,
    )
    stub = DecryptStub(address=0x2000, size=48, code=b"\x90" * 48)

    assert EncryptionScheme.RC4.value == "rc4"
    assert section.address == 0x1000
    assert stub.size == 48


def test_encryption_helpers_round_trip() -> None:
    data = b"Hello, World!"
    key = b"secret"

    encrypted = xor_encrypt(data, key)
    assert xor_encrypt(encrypted, key) == data

    rolling_encrypted, final_key = xor_rolling_encrypt(data, 0x55)
    assert rolling_encrypted != data
    assert final_key != 0x55

    assert len(add_sub_encrypt(data, 0x10)) == len(data)
    assert len(rc4_crypt(data, key)) == len(data)


def test_stub_and_pack_helpers_are_stable() -> None:
    key = b"\xaa\xbb\xcc\xdd"
    x64_stub = generate_xor_decrypt_stub_x64(key, 0x1000, 16)
    x86_stub = generate_xor_decrypt_stub_x86(key, 0x1000, 16)
    poly_stub = generate_polymorphic_stub_x64(key, 16, seed=123)
    packed, packed_key, unpack_stub = create_packed_binary(b"\x90" * 16, 0x1000)

    assert b"encrypted_data" in x64_stub
    assert b"encrypted_data" in x86_stub
    assert "decrypt_entry" in poly_stub
    assert len(packed) == 16
    assert len(packed_key) == 8
    assert len(unpack_stub) > 0
    assert calculate_unpacking_offset(17, alignment=16) == 32
