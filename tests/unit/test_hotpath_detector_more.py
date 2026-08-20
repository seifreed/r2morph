from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.profiling.hotpath_detector import HotPathDetector
from tests.utils.assertions import expect

_EXPECTED_HOT_BLOCKS_12288 = 0x3000
_EXPECTED_HOT_BLOCKS_4096 = 0x1000
_EXPECTED_HOT_BLOCKS_8192 = 0x2000


def test_hotpath_detector_identify_hot_blocks():
    detector = HotPathDetector(binary=None)
    blocks = [
        {"addr": 0x1000, "type": "head", "ninstr": 5, "inputs": 1},
        {"addr": 0x2000, "type": "body", "ninstr": 3, "inputs": 3},
        {"addr": 0x3000, "type": "body", "ninstr": 0, "inputs": 10},
    ]

    hot_blocks = detector._identify_hot_blocks(blocks)
    expect(not (_EXPECTED_HOT_BLOCKS_4096 not in hot_blocks))
    expect(not (_EXPECTED_HOT_BLOCKS_8192 not in hot_blocks))
    expect(_EXPECTED_HOT_BLOCKS_12288 not in hot_blocks)


def test_hotpath_detector_is_hot_path():
    detector = HotPathDetector(binary=None)
    hot_paths = {"sym.main": [0x1000, 0x2000]}

    expect(not (detector.is_hot_path("sym.main", 0x1000, hot_paths) is not True))
    expect(not (detector.is_hot_path("sym.main", 0x3000, hot_paths) is not False))


def test_hotpath_detector_detect_hot_paths_real():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        detector = HotPathDetector(bin_obj)
        hot_paths = detector.detect_hot_paths()

    expect(isinstance(hot_paths, dict))
