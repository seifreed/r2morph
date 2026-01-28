from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.obfuscation_detector import ObfuscationDetector


def test_obfuscation_detector_deeper_paths():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        detector = ObfuscationDetector()

        layers = detector.detect_code_packing_layers(bin_obj)
        assert isinstance(layers, dict)

        custom_vm = detector.detect_custom_virtualizer(bin_obj)
        assert isinstance(custom_vm, dict)

        meta = detector.detect_metamorphic_engine(bin_obj)
        assert isinstance(meta, dict)
        assert "polymorphic_ratio" in meta

        report = detector.get_comprehensive_report(bin_obj)
        assert isinstance(report, dict)
        assert "obfuscation_analysis" in report
