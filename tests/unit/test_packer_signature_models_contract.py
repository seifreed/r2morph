"""Contract tests for packer signature model exports."""

from r2morph.detection import PackerSignature as PublicPackerSignature
from r2morph.detection import PackerType as PublicPackerType
from r2morph.detection.packer_signature_models import (
    PackerSignature as ModelsPackerSignature,
)
from r2morph.detection.packer_signature_models import PackerType as ModelsPackerType
from r2morph.detection.packer_signatures import PackerSignatureDatabase


def test_packer_signature_models_are_reexported_from_detection_package():
    assert PublicPackerType is ModelsPackerType
    assert PublicPackerSignature is ModelsPackerSignature
    assert PackerSignatureDatabase is not None
