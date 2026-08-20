from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.obfuscation_detector import ObfuscationDetector
from tests.utils.assertions import expect


def test_obfuscation_detector_report_real_binary() -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    with Binary(source) as binary:
        binary.analyze()
        detector = ObfuscationDetector()
        result = detector.analyze_binary(binary)
        expect(result is not None)
        expect(isinstance(result.confidence_score, float))

        report = detector.get_comprehensive_report(binary)
        expect(not ("obfuscation_analysis" not in report))
        expect(not ("recommendations" not in report))
        expect(isinstance(report["recommendations"], list))
