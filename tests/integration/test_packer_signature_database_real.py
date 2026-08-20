from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.packer_signatures import PackerSignatureDatabase, PackerType
from tests.utils.assertions import expect


def test_packer_signature_detection_real_binary() -> None:
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        entropy = EntropyAnalyzer()
        db = PackerSignatureDatabase()

        packer = db.detect(bin_obj, entropy)
        expect(isinstance(packer, PackerType))

        layers = db.detect_packing_layers(bin_obj, entropy)
        expect(not ("layers_detected" not in layers))
        expect(not ("packers" not in layers))
