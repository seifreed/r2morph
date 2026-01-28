from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.profiling.hotpath_detector import HotPathDetector
from r2morph.profiling.profiler import BinaryProfiler


def test_hotpath_detector_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        detector = HotPathDetector(bin_obj)
        hot_paths = detector.detect_hot_paths()
        assert isinstance(hot_paths, dict)

        if hot_paths:
            func_name, blocks = next(iter(hot_paths.items()))
            assert isinstance(blocks, list)
            if blocks:
                assert detector.is_hot_path(func_name, blocks[0], hot_paths) is True


def test_profiler_parsing_and_cold_functions():
    profiler = BinaryProfiler(Path("dataset/elf_x86_64"))
    sample_output = """
      12.34%  bin  [.] sym.main
       2.00%  bin  [.] sym.helper
    """
    parsed = profiler._parse_perf_output(sample_output)
    assert parsed == ["sym.main", "sym.helper"]

    profiler.profile_data = {"hot_functions": ["sym.main"]}
    assert profiler.get_hot_functions() == {"sym.main"}
    cold = profiler.get_cold_functions(["sym.main", "sym.helper"])
    assert cold == {"sym.helper"}
    assert profiler.should_mutate_aggressively("sym.helper") is True
