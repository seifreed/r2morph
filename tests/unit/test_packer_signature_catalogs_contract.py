"""Contract tests for packer signature catalogs."""

from __future__ import annotations

from r2morph.detection import packer_signature_catalogs as catalogs
from r2morph.detection.packer_signatures import PackerSignatureDatabase, PackerType
from tests.utils.assertions import expect


def test_catalogs_cover_major_packer_families() -> None:
    signatures = (
        catalogs.vm_protector_signatures()
        + catalogs.compressor_signatures()
        + catalogs.protector_signatures()
        + catalogs.other_signatures()
    )

    expect(any(signature.packer_type == PackerType.VMPROTECT for signature in signatures))
    expect(any(signature.packer_type == PackerType.UPX for signature in signatures))
    expect(any(signature.packer_type == PackerType.ASPROTECT for signature in signatures))
    expect(any(signature.packer_type == PackerType.PESPIN for signature in signatures))


def test_database_uses_catalogs() -> None:
    db = PackerSignatureDatabase()
    expect(
        len(db.signatures)
        == len(
            catalogs.vm_protector_signatures()
            + catalogs.compressor_signatures()
            + catalogs.protector_signatures()
            + catalogs.other_signatures()
        )
    )
