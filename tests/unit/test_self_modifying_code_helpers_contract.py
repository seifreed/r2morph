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
from tests.utils.assertions import expect

_EXPECTED_CALCULATE_UNPACKING_OFFSET_17_ALIGNMENT_16_32 = 32
_EXPECTED_FINAL_KEY_85 = 0x55
_EXPECTED_LEN_PACKED_16 = 16
_EXPECTED_LEN_PACKED_KEY_8 = 8
_EXPECTED_SECTION_ADDRESS_4096 = 0x1000
_EXPECTED_STUB_SIZE_48 = 48


def test_models_and_enum_are_available() -> None:
    section = EncryptedSection(
        address=0x1000,
        size=32,
        original_bytes=b"\x90" * 32,
    )
    stub = DecryptStub(address=0x2000, size=48, code=b"\x90" * 48)

    expect(EncryptionScheme.RC4.value == "rc4")
    expect(section.address == _EXPECTED_SECTION_ADDRESS_4096)
    expect(stub.size == _EXPECTED_STUB_SIZE_48)


def test_encryption_helpers_round_trip() -> None:
    data = b"Hello, World!"
    key = b"secret"

    encrypted = xor_encrypt(data, key)
    expect(xor_encrypt(encrypted, key) == data)

    rolling_encrypted, final_key = xor_rolling_encrypt(data, 0x55)
    expect(rolling_encrypted != data)
    expect(final_key != _EXPECTED_FINAL_KEY_85)

    expect(len(add_sub_encrypt(data, 16)) == len(data))
    expect(len(rc4_crypt(data, key)) == len(data))


def test_stub_and_pack_helpers_are_stable() -> None:
    key = b"\xaa\xbb\xcc\xdd"
    x64_stub = generate_xor_decrypt_stub_x64(key, 16)
    x86_stub = generate_xor_decrypt_stub_x86(key, 16)
    poly_stub = generate_polymorphic_stub_x64(key, 16, seed=123)
    packed, packed_key, unpack_stub = create_packed_binary(b"\x90" * 16)

    expect(not (b"encrypted_data" not in x64_stub))
    expect(not (b"encrypted_data" not in x86_stub))
    expect(not ("decrypt_entry" not in poly_stub))
    expect(len(packed) == _EXPECTED_LEN_PACKED_16)
    expect(len(packed_key) == _EXPECTED_LEN_PACKED_KEY_8)
    expect(not (len(unpack_stub) <= 0))
    expect(calculate_unpacking_offset(17, alignment=16) == _EXPECTED_CALCULATE_UNPACKING_OFFSET_17_ALIGNMENT_16_32)
