from r2morph.mutations.api_hashing_hashes import (
    COMMON_LINUX_APIS,
    COMMON_WINDOWS_APIS,
    HASH_ALGORITHMS,
    hash_crc32,
    hash_djb2,
    hash_fnv1a,
    hash_ror7,
    hash_ror13,
    rol32,
    ror32,
)


def test_hash_primitives_and_known_api_sets_are_stable() -> None:
    assert ror32(0x12345678, 4) == 0x81234567
    assert rol32(0x12345678, 4) == 0x23456781
    assert hash_ror13("CreateFileA") == hash_ror13("createfilea")
    assert hash_ror7("test") != hash_ror13("test")
    assert hash_djb2("abc") != hash_fnv1a("abc")
    assert hash_crc32("test") == hash_crc32("TEST")
    assert "CreateFileA" in COMMON_WINDOWS_APIS
    assert "open" in COMMON_LINUX_APIS
    assert set(HASH_ALGORITHMS) == {"ror13", "ror7", "djb2", "fnv1a", "crc32"}
