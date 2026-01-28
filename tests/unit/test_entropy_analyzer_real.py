from pathlib import Path
import shutil

import pytest

from r2morph.detection.entropy_analyzer import EntropyAnalyzer


def test_entropy_analyzer_real_file(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    analyzer = EntropyAnalyzer()
    result = analyzer.analyze_file(binary_path)
    assert result.overall_entropy >= 0.0
    assert isinstance(result.section_entropies, dict)
    assert isinstance(result.suspicious_sections, list)

    # Compare with a slightly modified copy
    morphed = tmp_path / "morphed_entropy"
    shutil.copy(binary_path, morphed)
    data = morphed.read_bytes()
    if data:
        morphed.write_bytes(bytes([data[0] ^ 0xAA]) + data[1:])

    orig_entropy, morph_entropy, delta = analyzer.compare_entropy(binary_path, morphed)
    assert isinstance(delta, float)
    assert orig_entropy >= 0.0
    assert morph_entropy >= 0.0

    blocks = analyzer.visualize_entropy(binary_path, block_size=128)
    assert blocks
