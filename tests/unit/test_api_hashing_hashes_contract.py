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
from tests.utils.assertions import expect

_EXPECTED_ROL32_0X12345678_4_591751041 = 0x23456781
_EXPECTED_ROR32_0X12345678_4_2166572391 = 0x81234567


def test_hash_primitives_and_known_api_sets_are_stable() -> None:
    expect(ror32(305419896, 4) == _EXPECTED_ROR32_0X12345678_4_2166572391)
    expect(rol32(305419896, 4) == _EXPECTED_ROL32_0X12345678_4_591751041)
    expect(hash_ror13("CreateFileA") == hash_ror13("createfilea"))
    expect(hash_ror7("test") != hash_ror13("test"))
    expect(hash_djb2("abc") != hash_fnv1a("abc"))
    expect(hash_crc32("test") == hash_crc32("TEST"))
    expect(not ("CreateFileA" not in COMMON_WINDOWS_APIS))
    expect(not ("open" not in COMMON_LINUX_APIS))
    expect(set(HASH_ALGORITHMS) == {"ror13", "ror7", "djb2", "fnv1a", "crc32"})
