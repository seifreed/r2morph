from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.profiling.hotpath_detector import HotPathDetector


def test_hotpath_detector_identify_hot_blocks():
    detector = HotPathDetector(binary=None)
    blocks = [
        {"addr": 0x1000, "type": "head", "ninstr": 5, "inputs": 1},
        {"addr": 0x2000, "type": "body", "ninstr": 3, "inputs": 3},
        {"addr": 0x3000, "type": "body", "ninstr": 0, "inputs": 10},
    ]

    hot_blocks = detector._identify_hot_blocks(blocks)
    assert 0x1000 in hot_blocks
    assert 0x2000 in hot_blocks
    assert 0x3000 not in hot_blocks


def test_hotpath_detector_is_hot_path():
    detector = HotPathDetector(binary=None)
    hot_paths = {"sym.main": [0x1000, 0x2000]}

    assert detector.is_hot_path("sym.main", 0x1000, hot_paths) is True
    assert detector.is_hot_path("sym.main", 0x3000, hot_paths) is False


def test_hotpath_detector_detect_hot_paths_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        detector = HotPathDetector(bin_obj)
        hot_paths = detector.detect_hot_paths()

    assert isinstance(hot_paths, dict)
