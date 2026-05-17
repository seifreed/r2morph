"""Characterization tests for the AES substitution tables in r2morph.crypto.aes.

These lock the exact contents of SBOX / INV_SBOX / RCON. They exist because
the tables were reflowed by Black when the legacy ``# fmt: off`` pragma was
removed (commit 563f70d): the values must remain byte-identical and must keep
their defining mathematical relationships, independent of formatting.

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


class TestSBox:
    def test_sbox_length_is_256(self) -> None:
        assert len(SBOX) == 256

    def test_sbox_is_a_permutation_of_0_255(self) -> None:
        # A correct AES S-box is a bijection over the byte range.
        assert sorted(SBOX) == list(range(256))

    def test_sbox_values_are_byte_sized(self) -> None:
        assert all(0 <= value <= 0xFF for value in SBOX)

    def test_sbox_anchor_values_match_fips_197(self) -> None:
        # Official AES S-box reference values (FIPS-197, Figure 7).
        assert SBOX[0x00] == 0x63
        assert SBOX[0x01] == 0x7C
        assert SBOX[0x10] == 0xCA
        assert SBOX[0x53] == 0xED
        assert SBOX[0x7F] == 0xD2
        assert SBOX[0xFF] == 0x16


class TestInvSBox:
    def test_inv_sbox_length_is_256(self) -> None:
        assert len(INV_SBOX) == 256

    def test_inv_sbox_is_a_permutation_of_0_255(self) -> None:
        assert sorted(INV_SBOX) == list(range(256))

    def test_inv_sbox_anchor_values_match_fips_197(self) -> None:
        # Official inverse AES S-box reference values (FIPS-197, Figure 14).
        assert INV_SBOX[0x00] == 0x52
        assert INV_SBOX[0x63] == 0x00
        assert INV_SBOX[0x16] == 0xFF


class TestSBoxInverseRelationship:
    def test_inv_sbox_is_left_inverse_of_sbox(self) -> None:
        assert all(INV_SBOX[SBOX[i]] == i for i in range(256))

    def test_inv_sbox_is_right_inverse_of_sbox(self) -> None:
        assert all(SBOX[INV_SBOX[i]] == i for i in range(256))


class TestRcon:
    def test_rcon_exact_values(self) -> None:
        # AES round constants: powers of x (0x02) in GF(2^8), 10 entries.
        assert RCON == [
            0x01,
            0x02,
            0x04,
            0x08,
            0x10,
            0x20,
            0x40,
            0x80,
            0x1B,
            0x36,
        ]
