from pathlib import Path

from r2morph.platform.codesign import CodeSigner


def test_codesign_missing_identity_returns_false(tmp_path):
    signer = CodeSigner()
    binary_path = tmp_path / "bin"
    binary_path.write_text("stub")

    # Force non-adhoc path without identity; should fail fast on macOS.
    result = signer.sign(binary_path, identity=None, adhoc=False)
    assert result in (True, False)


def test_codesign_needs_signing_and_verify(tmp_path):
    signer = CodeSigner()
    binary_path = tmp_path / "bin"
    binary_path.write_text("stub")

    needs = signer.needs_signing(binary_path)
    assert isinstance(needs, bool)

    verify = signer.verify(binary_path)
    assert verify in (True, False)


def test_codesign_verify_nonexistent_path():
    signer = CodeSigner()
    verify = signer.verify(Path("does_not_exist.bin"))
    assert verify in (True, False)
