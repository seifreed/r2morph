from __future__ import annotations

import logging
from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache
from r2morph.core.analysis_cache_lifecycle import start_cleanup_thread, stop_cleanup_thread


def test_analysis_cache_lifecycle_helpers_start_and_stop_thread(tmp_path: Path) -> None:
    cache = AnalysisCache(cache_dir=tmp_path, enable_background_cleanup=False)
    lifecycle_logger = logging.getLogger("r2morph.core.analysis_cache_lifecycle.test")

    start_cleanup_thread(cache, lifecycle_logger)
    assert cache._cleanup_thread is not None
    assert cache._cleanup_thread.is_alive()

    stop_cleanup_thread(cache, lifecycle_logger)
    assert not cache._cleanup_thread.is_alive()
