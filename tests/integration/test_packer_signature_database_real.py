from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.packer_signatures import PackerSignatureDatabase, PackerType


def test_packer_signature_detection_real_binary() -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        entropy = EntropyAnalyzer()
        db = PackerSignatureDatabase()

        packer = db.detect(bin_obj, entropy)
        assert isinstance(packer, PackerType)

        layers = db.detect_packing_layers(bin_obj, entropy)
        assert "layers_detected" in layers
        assert "packers" in layers
