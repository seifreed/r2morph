"""
Unit tests for analysis cache.
"""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from r2morph.core.analysis_cache import (
    AnalysisCache,
    CacheEntry,
    CacheKey,
    CacheStats,
    CacheStorage,
    compute_binary_hash,
    compute_partial_hash,
)


class TestCacheKey:
    def test_cache_key_creation(self):
        key = CacheKey(
            binary_hash="abc123",
            analysis_type="cfg",
            options_hash="def456",
            version="0.2.0",
        )
        assert key.binary_hash == "abc123"
        assert key.analysis_type == "cfg"

    def test_cache_key_to_string(self):
        key = CacheKey(
            binary_hash="abc123",
            analysis_type="cfg",
            options_hash="def456",
        )
        s = key.to_string()
        assert len(s) == 32
        assert isinstance(s, str)

    def test_cache_key_to_path(self):
        key = CacheKey(
            binary_hash="abc123",
            analysis_type="cfg",
            options_hash="def456",
        )
        path = key.to_path()
        assert "/" in path
        assert path.endswith(".cache")

    def test_cache_key_consistency(self):
        key1 = CacheKey(
            binary_hash="abc123",
            analysis_type="cfg",
            options_hash="def456",
        )
        key2 = CacheKey(
            binary_hash="abc123",
            analysis_type="cfg",
            options_hash="def456",
        )
        assert key1.to_string() == key2.to_string()

    def test_cache_key_different_types(self):
        key1 = CacheKey(binary_hash="abc", analysis_type="cfg", options_hash="def")
        key2 = CacheKey(binary_hash="abc", analysis_type="call_graph", options_hash="def")
        assert key1.to_string() != key2.to_string()


class TestCacheStats:
    def test_cache_stats_defaults(self):
        stats = CacheStats()
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.evictions == 0

    def test_cache_stats_hit_rate(self):
        stats = CacheStats(hits=75, misses=25)
        assert stats.hit_rate == 0.75

    def test_cache_stats_hit_rate_zero(self):
        stats = CacheStats()
        assert stats.hit_rate == 0.0

    def test_cache_stats_to_dict(self):
        stats = CacheStats(hits=10, misses=5, entry_count=3)
        d = stats.to_dict()
        assert d["hits"] == 10
        assert d["misses"] == 5
        assert d["hit_rate"] == 10 / 15
        assert d["entry_count"] == 3


class TestCacheEntry:
    def test_cache_entry_creation(self):
        key = CacheKey(binary_hash="abc", analysis_type="cfg", options_hash="def")
        entry = CacheEntry(key=key, data={"test": "data"})

        assert entry.data == {"test": "data"}
        assert entry.access_count == 0

    def test_cache_entry_touch(self):
        key = CacheKey(binary_hash="abc", analysis_type="cfg", options_hash="def")
        entry = CacheEntry(key=key, data="test")

        entry.touch()
        assert entry.access_count == 1

        entry.touch()
        assert entry.access_count == 2


class TestAnalysisCache:
    @pytest.fixture
    def temp_cache_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def cache(self, temp_cache_dir):
        return AnalysisCache(cache_dir=temp_cache_dir, max_size_mb=10)

    @pytest.fixture
    def sample_binary(self):
        return b"\x7fELF" + b"\x00" * 100

    def test_cache_initialization(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir)
        assert cache.cache_dir == temp_cache_dir
        assert cache.cache_dir.exists()

    def test_cache_initialization_default(self):
        cache = AnalysisCache()
        assert cache.cache_dir.exists()
        assert ".cache" in str(cache.cache_dir)

    def test_get_miss(self, cache, sample_binary):
        result = cache.get(sample_binary, "cfg")
        assert result is None
        assert cache.get_stats().misses == 1

    def test_set_and_get(self, cache, sample_binary):
        analysis_result = {"blocks": [1, 2, 3], "edges": [(1, 2), (2, 3)]}
        cache.set(sample_binary, "cfg", analysis_result)

        result = cache.get(sample_binary, "cfg")
        assert result == analysis_result
        assert cache.get_stats().hits == 1

    def test_set_with_options(self, cache, sample_binary):
        options = {"depth": 2, "analyze_loops": True}
        cache.set(sample_binary, "cfg", {"data": 1}, options=options)

        result = cache.get(sample_binary, "cfg", options=options)
        assert result == {"data": 1}

    def test_different_options_different_cache(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"v": 1}, options={"opt": "a"})
        cache.set(sample_binary, "cfg", {"v": 2}, options={"opt": "b"})

        result_a = cache.get(sample_binary, "cfg", options={"opt": "a"})
        result_b = cache.get(sample_binary, "cfg", options={"opt": "b"})

        assert result_a == {"v": 1}
        assert result_b == {"v": 2}

    def test_invalidate_all_for_binary(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"data": 1})
        cache.set(sample_binary, "call_graph", {"data": 2})

        removed = cache.invalidate(sample_binary)
        assert removed == 2

        assert cache.get(sample_binary, "cfg") is None
        assert cache.get(sample_binary, "call_graph") is None

    def test_invalidate_specific_analysis(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"data": 1})
        cache.set(sample_binary, "call_graph", {"data": 2})

        removed = cache.invalidate(sample_binary, analysis_type="cfg")
        assert removed == 1

        assert cache.get(sample_binary, "cfg") is None
        assert cache.get(sample_binary, "call_graph") is not None

    def test_clear(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"data": 1})
        cache.set(sample_binary, "call_graph", {"data": 2})

        removed = cache.clear()
        assert removed == 2

        stats = cache.get_stats()
        assert stats.entry_count == 0

    def test_size_limit(self, temp_cache_dir, sample_binary):
        cache = AnalysisCache(cache_dir=temp_cache_dir, max_size_mb=0.001)

        for i in range(100):
            cache.set(sample_binary, f"analysis_{i}", {"data": "x" * 100})

        stats = cache.refresh_stats()
        assert stats.total_size_bytes <= 1024

    def test_get_entry_metadata(self, cache, sample_binary):
        cache.set(
            sample_binary,
            "cfg",
            {"data": 1},
            metadata={"source": "test", "version": "1.0"},
        )

        metadata = cache.get_entry_metadata(sample_binary, "cfg")
        assert metadata is not None
        assert metadata["metadata"]["source"] == "test"
        assert "created_at" in metadata

    def test_list_entries(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"data": 1})
        cache.set(sample_binary, "call_graph", {"data": 2})

        entries = cache.list_entries()
        assert len(entries) == 2

        cfg_entries = cache.list_entries(analysis_type="cfg")
        assert len(cfg_entries) == 1
        assert cfg_entries[0]["analysis_type"] == "cfg"

    def test_cache_with_metadata(self, cache, sample_binary):
        metadata = {"source": "unit_test", "regions": [{"offset": 0, "size": 100}]}
        cache.set(sample_binary, "cfg", {"data": 1}, metadata=metadata)

        result_metadata = cache.get_entry_metadata(sample_binary, "cfg")
        assert result_metadata["metadata"]["source"] == "unit_test"


class TestCacheStorage:
    @pytest.fixture
    def temp_storage_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_pickle_storage_save_load(self, temp_storage_dir):
        storage = CacheStorage(cache_dir=temp_storage_dir, storage_type="pickle")

        storage.save("test_key", {"data": [1, 2, 3]})
        loaded = storage.load("test_key")

        assert loaded == {"data": [1, 2, 3]}

    def test_json_storage_save_load(self, temp_storage_dir):
        storage = CacheStorage(cache_dir=temp_storage_dir, storage_type="json")

        storage.save("test_key", {"data": [1, 2, 3]})
        loaded = storage.load("test_key")

        assert loaded == {"data": [1, 2, 3]}

    def test_storage_exists(self, temp_storage_dir):
        storage = CacheStorage(cache_dir=temp_storage_dir)

        storage.save("test_key", "data")
        assert storage.exists("test_key")
        assert not storage.exists("nonexistent")

    def test_storage_delete(self, temp_storage_dir):
        storage = CacheStorage(cache_dir=temp_storage_dir)

        storage.save("test_key", "data")
        assert storage.delete("test_key")
        assert not storage.exists("test_key")
        assert not storage.delete("nonexistent")

    def test_storage_none_cache_dir(self):
        storage = CacheStorage(cache_dir=None)

        storage.save("test_key", "data")
        assert storage.load("test_key") is None
        assert not storage.exists("test_key")


class TestHashing:
    @pytest.fixture
    def temp_binary(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            yield Path(f.name)

    def test_compute_binary_hash(self, temp_binary):
        hash1 = compute_binary_hash(temp_binary)
        hash2 = compute_binary_hash(temp_binary)

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_compute_partial_hash(self, temp_binary):
        hash1 = compute_partial_hash(temp_binary, 0, 50)
        hash2 = compute_partial_hash(temp_binary, 0, 50)

        assert hash1 == hash2
        assert len(hash1) == 32

    def test_different_files_different_hash(self, temp_binary):
        hash1 = compute_binary_hash(temp_binary)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"a" * 200)
            other_path = Path(f.name)

        hash2 = compute_binary_hash(other_path)
        assert hash1 != hash2
        other_path.unlink(missing_ok=True)

    def test_binary_hash_stability(self, temp_binary):
        hashes = [compute_binary_hash(temp_binary) for _ in range(5)]
        assert all(h == hashes[0] for h in hashes)


class TestCacheIntegration:
    @pytest.fixture
    def temp_cache_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_simulated_cfg_analysis(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir)
        binary = b"BINARY_DATA"

        cfg_result = {
            "blocks": [
                {"address": 0x1000, "size": 16},
                {"address": 0x1010, "size": 20},
            ],
            "edges": [(0x1000, 0x1010)],
        }

        cache.set(binary, "cfg", cfg_result)

        cached = cache.get(binary, "cfg")
        assert cached == cfg_result
        assert cached["blocks"][0]["address"] == 0x1000

    def test_simulated_multiple_analyses(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir)
        binary = b"BINARY_DATA"

        cache.set(binary, "cfg", {"blocks": [1, 2]})
        cache.set(binary, "call_graph", {"nodes": [1, 2, 3]})
        cache.set(binary, "type_inference", {"types": ["int", "ptr"]})

        assert cache.get(binary, "cfg") == {"blocks": [1, 2]}
        assert cache.get(binary, "call_graph") == {"nodes": [1, 2, 3]}
        assert cache.get(binary, "type_inference") == {"types": ["int", "ptr"]}

    def test_persistence_across_instances(self, temp_cache_dir):
        binary = b"BINARY_DATA"

        cache1 = AnalysisCache(cache_dir=temp_cache_dir)
        cache1.set(binary, "cfg", {"persistent": "data"})

        cache2 = AnalysisCache(cache_dir=temp_cache_dir)
        result = cache2.get(binary, "cfg")

        assert result == {"persistent": "data"}

    def test_stats_tracking(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir)
        binary = b"BINARY_DATA"

        cache.get(binary, "cfg")
        cache.set(binary, "cfg", {"data": 1})
        cache.get(binary, "cfg")
        cache.get(binary, "cfg")

        stats = cache.get_stats()
        assert stats.misses == 1
        assert stats.hits == 2
        assert stats.hit_rate == 2 / 3


class TestBackgroundCleanup:
    @pytest.fixture
    def temp_cache_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_cleanup_expired_removes_old_entries(self, temp_cache_dir):
        from datetime import timedelta
        from r2morph.core.analysis_cache import CacheEntry

        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        binary = b"BINARY_DATA"

        cache.set(binary, "cfg", {"data": 1})

        key = CacheKey(
            binary_hash=cache._hash_binary(binary),
            analysis_type="cfg",
            options_hash=cache._hash_options({}),
        )
        old_entry = CacheEntry(key=key, data={"data": 2})
        old_entry.created_at = datetime.now() - timedelta(days=100)
        old_entry.accessed_at = datetime.now() - timedelta(days=100)
        cache._save_entry(old_entry)

        removed = cache.cleanup_expired(max_age_days=30)
        assert removed == 1

    def test_cleanup_expired_keeps_recent(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        binary = b"BINARY_DATA"

        cache.set(binary, "cfg", {"data": 1})

        removed = cache.cleanup_expired(max_age_days=30)
        assert removed == 0

        result = cache.get(binary, "cfg")
        assert result == {"data": 1}

    def test_cleanup_low_access_removes_unused(self, temp_cache_dir):
        from datetime import timedelta
        from r2morph.core.analysis_cache import CacheEntry

        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        binary = b"BINARY_DATA"

        key = CacheKey(
            binary_hash=cache._hash_binary(binary),
            analysis_type="cfg",
            options_hash=cache._hash_options({}),
        )
        old_entry = CacheEntry(key=key, data={"data": 1})
        old_entry.created_at = datetime.now() - timedelta(days=100)
        old_entry.accessed_at = datetime.now() - timedelta(days=100)
        cache._save_entry(old_entry)

        removed = cache.cleanup_low_access(min_access_count=2, max_age_days=7)
        assert removed == 1

    def test_cleanup_low_access_keeps_frequently_accessed(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        binary = b"BINARY_DATA"

        cache.set(binary, "cfg", {"data": 1})
        cache.get(binary, "cfg")
        cache.get(binary, "cfg")

        removed = cache.cleanup_low_access(min_access_count=2, max_age_days=0)
        assert removed == 0

        result = cache.get(binary, "cfg")
        assert result == {"data": 1}

    def test_background_cleanup_disabled(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        assert cache._cleanup_thread is None

    def test_background_cleanup_enabled(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=True)
        assert cache._cleanup_thread is not None
        assert cache._cleanup_thread.is_alive()

        cache.stop_cleanup_thread()
        assert not cache._cleanup_thread.is_alive()

    def test_stop_cleanup_thread(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=True)

        assert cache._cleanup_thread.is_alive()
        cache.stop_cleanup_thread()

        import time

        time.sleep(0.1)
        assert not cache._cleanup_thread.is_alive()

    def test_cleanup_with_custom_interval(self, temp_cache_dir):
        cache = AnalysisCache(
            cache_dir=temp_cache_dir,
            cleanup_interval_seconds=60,
            enable_background_cleanup=True,
        )
        assert cache.cleanup_interval_seconds == 60

        cache.stop_cleanup_thread()
