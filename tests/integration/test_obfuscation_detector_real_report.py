from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.obfuscation_detector import ObfuscationDetector


def test_obfuscation_detector_report_real_binary() -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    with Binary(source) as binary:
        binary.analyze()
        detector = ObfuscationDetector()
        result = detector.analyze_binary(binary)
        assert result is not None
        assert isinstance(result.confidence_score, float)

        report = detector.get_comprehensive_report(binary)
        assert "obfuscation_analysis" in report
        assert "recommendations" in report
        assert isinstance(report["recommendations"], list)
