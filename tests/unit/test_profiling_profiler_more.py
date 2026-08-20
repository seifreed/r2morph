from pathlib import Path

from r2morph.profiling.profiler import BinaryProfiler
from tests.utils.assertions import expect


def test_profiler_parse_perf_output_extracts_symbols():
    output = """
  12.34%  binary  binary  [.] sym._start
   5.67%  binary  binary  [.] sym.main
   0.12%  binary  binary  [.] sym.helper
"""
    profiler = BinaryProfiler(Path("fake"))
    hot = profiler._parse_perf_output(output)

    expect(hot[:2] == ["sym._start", "sym.main"])
    expect(not ("sym.helper" not in hot))


def test_profiler_hot_and_cold_functions():
    profiler = BinaryProfiler(Path("fake"))
    profiler.profile_data = {"hot_functions": ["sym.main", "sym.loop"]}

    hot = profiler.get_hot_functions()
    expect(hot == {"sym.main", "sym.loop"})

    cold = profiler.get_cold_functions(["sym.main", "sym.loop", "sym.cold"])
    expect(cold == {"sym.cold"})


def test_profiler_should_mutate_aggressively():
    profiler = BinaryProfiler(Path("fake"))
    profiler.profile_data = {"hot_functions": ["sym.main"]}

    expect(not (profiler.should_mutate_aggressively("sym.helper") is not True))
    expect(not (profiler.should_mutate_aggressively("sym.main") is not False))
