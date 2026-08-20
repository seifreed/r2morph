"""Characterization tests for the AES substitution tables in r2morph.crypto.aes.

These lock the exact contents of SBOX / INV_SBOX / RCON. They exist because
the tables were reformatted in commit 563f70d: the values must remain
byte-identical and keep their defining mathematical relationships independent
of formatting.

Scope note: these tests deliberately cover only the tables, which are correct
and stable. The block/string cipher functions (aes_encrypt_block /
aes_decrypt_block / aes_encrypt_string) are NOT characterized here because
they currently raise IndexError for any input (round-key word indexed out of
range); enshrining that broken behavior in a test would be wrong. That defect
is tracked separately.

No mocks / monkeypatch (CLAUDE.md §4): the real module is imported and the
real table values are asserted, including anchor values from the AES
specification (FIPS-197).
"""

from r2morph.crypto.aes import INV_SBOX, RCON, SBOX
from tests.utils.assertions import expect

_EXPECTED_0_255 = 0xFF
_EXPECTED_INV_SBOX_0X00_82 = 0x52
_EXPECTED_INV_SBOX_0X16_255 = 0xFF
_EXPECTED_LEN_INV_SBOX_256 = 256
_EXPECTED_LEN_SBOX_256 = 256
_EXPECTED_SBOX_0X00_99 = 0x63
_EXPECTED_SBOX_0X01_124 = 0x7C
_EXPECTED_SBOX_0X10_202 = 0xCA
_EXPECTED_SBOX_0X53_237 = 0xED
_EXPECTED_SBOX_0X7F_210 = 0xD2
_EXPECTED_SBOX_0XFF_22 = 0x16


class TestSBox:
    def test_sbox_length_is_256(self) -> None:
        expect(len(SBOX) == _EXPECTED_LEN_SBOX_256)

    def test_sbox_is_a_permutation_of_0_255(self) -> None:
        # A correct AES S-box is a bijection over the byte range.
        expect(sorted(SBOX) == list(range(256)))

    def test_sbox_values_are_byte_sized(self) -> None:
        expect(all(0 <= value <= _EXPECTED_0_255 for value in SBOX))

    def test_sbox_anchor_values_match_fips_197(self) -> None:
        # Official AES S-box reference values (FIPS-197, Figure 7).
        expect(SBOX[0] == _EXPECTED_SBOX_0X00_99)
        expect(SBOX[1] == _EXPECTED_SBOX_0X01_124)
        expect(SBOX[16] == _EXPECTED_SBOX_0X10_202)
        expect(SBOX[83] == _EXPECTED_SBOX_0X53_237)
        expect(SBOX[127] == _EXPECTED_SBOX_0X7F_210)
        expect(SBOX[255] == _EXPECTED_SBOX_0XFF_22)


class TestInvSBox:
    def test_inv_sbox_length_is_256(self) -> None:
        expect(len(INV_SBOX) == _EXPECTED_LEN_INV_SBOX_256)

    def test_inv_sbox_is_a_permutation_of_0_255(self) -> None:
        expect(sorted(INV_SBOX) == list(range(256)))

    def test_inv_sbox_anchor_values_match_fips_197(self) -> None:
        # Official inverse AES S-box reference values (FIPS-197, Figure 14).
        expect(INV_SBOX[0] == _EXPECTED_INV_SBOX_0X00_82)
        expect(INV_SBOX[99] == 0)
        expect(INV_SBOX[22] == _EXPECTED_INV_SBOX_0X16_255)


class TestSBoxInverseRelationship:
    def test_inv_sbox_is_left_inverse_of_sbox(self) -> None:
        expect(all(INV_SBOX[SBOX[i]] == i for i in range(256)))

    def test_inv_sbox_is_right_inverse_of_sbox(self) -> None:
        expect(all(SBOX[INV_SBOX[i]] == i for i in range(256)))


class TestRcon:
    def test_rcon_exact_values(self) -> None:
        # AES round constants: powers of x (0x02) in GF(2^8), 10 entries.
        expect(RCON == [1, 2, 4, 8, 16, 32, 64, 128, 27, 54])
