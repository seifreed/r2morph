from __future__ import annotations

import logging
from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache
from r2morph.core.analysis_cache_lifecycle import _should_log_failure, start_cleanup_thread, stop_cleanup_thread
from tests.utils.assertions import expect, expect_all


def test_analysis_cache_lifecycle_helpers_start_and_stop_thread(tmp_path: Path) -> None:
    cache = AnalysisCache(cache_dir=tmp_path, enable_background_cleanup=False)
    lifecycle_logger = logging.getLogger("r2morph.core.analysis_cache_lifecycle.test")

    start_cleanup_thread(cache, lifecycle_logger)
    expect(cache._cleanup_thread is not None)
    expect(cache._cleanup_thread.is_alive())

    stop_cleanup_thread(cache, lifecycle_logger)
    expect(not (cache._cleanup_thread.is_alive()))


def test_analysis_cache_cleanup_failure_sampling_is_logarithmic() -> None:
    logged_failures = [count for count in range(1, 17) if _should_log_failure(count)]

    expect_all(
        logged_failures == [1, 2, 4, 8, 16],
        not _should_log_failure(0),
    )
