from pathlib import Path

from r2morph.profiling.profiler import BinaryProfiler


def test_profiler_parse_perf_output_extracts_symbols():
    output = """
  12.34%  binary  binary  [.] sym._start
   5.67%  binary  binary  [.] sym.main
   0.12%  binary  binary  [.] sym.helper
"""
    profiler = BinaryProfiler(Path("fake"))
    hot = profiler._parse_perf_output(output)

    assert hot[:2] == ["sym._start", "sym.main"]
    assert "sym.helper" in hot


def test_profiler_hot_and_cold_functions():
    profiler = BinaryProfiler(Path("fake"))
    profiler.profile_data = {"hot_functions": ["sym.main", "sym.loop"]}

    hot = profiler.get_hot_functions()
    assert hot == {"sym.main", "sym.loop"}

    cold = profiler.get_cold_functions(["sym.main", "sym.loop", "sym.cold"])
    assert cold == {"sym.cold"}


def test_profiler_should_mutate_aggressively():
    profiler = BinaryProfiler(Path("fake"))
    profiler.profile_data = {"hot_functions": ["sym.main"]}

    assert profiler.should_mutate_aggressively("sym.helper") is True
    assert profiler.should_mutate_aggressively("sym.main") is False
