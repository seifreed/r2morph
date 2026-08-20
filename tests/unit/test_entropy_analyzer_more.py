from pathlib import Path

import pytest

from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult
from tests.utils.assertions import expect

_EXPECTED_0_0_8_0 = 8.0
_EXPECTED_0_0_8_0_2 = 8.0
_EXPECTED_0_0_8_0_3 = 8.0
_EXPECTED_0_0_8_0_4 = 8.0
_EXPECTED_ABS_DELTA_MORPH_ENTROPY_ORIG_ENTROPY_1e_06 = 1e-6
_EXPECTED_LEN_BLOCKS_4 = 4


def test_entropy_analyzer_analyze_file_low_entropy(tmp_path: Path):
    sample = tmp_path / "zeros.bin"
    sample.write_bytes(b"\x00" * 2048)

    analyzer = EntropyAnalyzer()
    result = analyzer.analyze_file(sample)

    expect(isinstance(result, EntropyResult))
    expect(0.0 <= result.overall_entropy <= _EXPECTED_0_0_8_0)
    expect(not (result.is_packed is not False))
    expect(isinstance(result.section_entropies, dict))
    expect(isinstance(result.suspicious_sections, list))
    expect(not ("Normal entropy" not in result.analysis))


def test_entropy_analyzer_compare_entropy_delta(tmp_path: Path):
    orig = tmp_path / "orig.bin"
    morph = tmp_path / "morph.bin"
    orig.write_bytes(b"\x00" * 1024)
    morph.write_bytes(bytes(range(256)) * 4)

    analyzer = EntropyAnalyzer()
    orig_entropy, morph_entropy, delta = analyzer.compare_entropy(orig, morph)

    expect(0.0 <= orig_entropy <= _EXPECTED_0_0_8_0_2)
    expect(0.0 <= morph_entropy <= _EXPECTED_0_0_8_0_3)
    expect(not (abs(delta - (morph_entropy - orig_entropy)) >= _EXPECTED_ABS_DELTA_MORPH_ENTROPY_ORIG_ENTROPY_1e_06))


def test_entropy_analyzer_visualize_blocks(tmp_path: Path):
    sample = tmp_path / "blocks.bin"
    sample.write_bytes(bytes(range(256)) * 4)

    analyzer = EntropyAnalyzer()
    blocks = analyzer.visualize_entropy(sample, block_size=256)

    expect(len(blocks) == _EXPECTED_LEN_BLOCKS_4)
    expect(all(0.0 <= value <= _EXPECTED_0_0_8_0_4 for value in blocks))


def test_entropy_analyzer_sections_real():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    analyzer = EntropyAnalyzer()
    result = analyzer.analyze_file(binary_path)

    expect(isinstance(result.section_entropies, dict))
    expect(isinstance(result.suspicious_sections, list))
