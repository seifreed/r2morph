"""
Unit tests for analysis cache.
"""

import importlib
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
from tests.utils.assertions import expect

_EXPECTED_CACHED_BLOCKS_0_ADDRESS_4096 = 0x1000
_EXPECTED_CACHE_CLEANUP_INTERVAL_SECONDS_60 = 60
_EXPECTED_D_ENTRY_COUNT_3 = 3
_EXPECTED_D_HITS_10 = 10
_EXPECTED_D_MISSES_5 = 5
_EXPECTED_ENTRY_ACCESS_COUNT_2 = 2
_EXPECTED_LEN_ENTRIES_2 = 2
_EXPECTED_LEN_HASH1_32 = 32
_EXPECTED_LEN_HASH1_64 = 64
_EXPECTED_LEN_S_32 = 32
_EXPECTED_REMOVED_2 = 2
_EXPECTED_REMOVED_2_2 = 2
_EXPECTED_STATS_HITS_2 = 2
_EXPECTED_STATS_HIT_RATE_0_75 = 0.75
_EXPECTED_STATS_TOTAL_SIZE_BYTES_2048 = 2048


class TestCacheKey:
    def test_cache_key_creation(self):
        key = CacheKey(
            binary_hash="abc123",
            analysis_type="cfg",
            options_hash="def456",
            version="0.2.0",
        )
        expect(key.binary_hash == "abc123")
        expect(key.analysis_type == "cfg")

    def test_cache_key_to_string(self):
        key = CacheKey(
            binary_hash="abc123",
            analysis_type="cfg",
            options_hash="def456",
        )
        s = key.to_string()
        expect(len(s) == _EXPECTED_LEN_S_32)
        expect(isinstance(s, str))

    def test_cache_key_to_path(self):
        key = CacheKey(
            binary_hash="abc123",
            analysis_type="cfg",
            options_hash="def456",
        )
        path = key.to_path()
        expect(not ("/" not in path))
        expect(path.endswith(".cache"))

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
        expect(key1.to_string() == key2.to_string())

    def test_cache_key_different_types(self):
        key1 = CacheKey(binary_hash="abc", analysis_type="cfg", options_hash="def")
        key2 = CacheKey(binary_hash="abc", analysis_type="call_graph", options_hash="def")
        expect(key1.to_string() != key2.to_string())


class TestCacheStats:
    def test_cache_stats_defaults(self):
        stats = CacheStats()
        expect(stats.hits == 0)
        expect(stats.misses == 0)
        expect(stats.evictions == 0)

    def test_cache_stats_hit_rate(self):
        stats = CacheStats(hits=75, misses=25)
        expect(stats.hit_rate == _EXPECTED_STATS_HIT_RATE_0_75)

    def test_cache_stats_hit_rate_zero(self):
        stats = CacheStats()
        expect(stats.hit_rate == 0.0)

    def test_cache_stats_to_dict(self):
        stats = CacheStats(hits=10, misses=5, entry_count=3)
        d = stats.to_dict()
        expect(d["hits"] == _EXPECTED_D_HITS_10)
        expect(d["misses"] == _EXPECTED_D_MISSES_5)
        expect(d["hit_rate"] == 10 / 15)
        expect(d["entry_count"] == _EXPECTED_D_ENTRY_COUNT_3)


class TestCacheEntry:
    def test_cache_entry_creation(self):
        key = CacheKey(binary_hash="abc", analysis_type="cfg", options_hash="def")
        entry = CacheEntry(key=key, data={"test": "data"})

        expect(entry.data == {"test": "data"})
        expect(entry.access_count == 0)

    def test_cache_entry_touch(self):
        key = CacheKey(binary_hash="abc", analysis_type="cfg", options_hash="def")
        entry = CacheEntry(key=key, data="test")

        entry.touch()
        expect(entry.access_count == 1)

        entry.touch()
        expect(entry.access_count == _EXPECTED_ENTRY_ACCESS_COUNT_2)


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
        expect(cache.cache_dir == temp_cache_dir)
        expect(cache.cache_dir.exists())

    def test_cache_initialization_default(self):
        cache = AnalysisCache()
        expect(cache.cache_dir.exists())
        expect(not (".cache" not in str(cache.cache_dir)))

    def test_get_miss(self, cache, sample_binary):
        result = cache.get(sample_binary, "cfg")
        expect(not (result is not None))
        expect(cache.get_stats().misses == 1)

    def test_set_and_get(self, cache, sample_binary):
        analysis_result = {"blocks": [1, 2, 3], "edges": [(1, 2), (2, 3)]}
        cache.set(sample_binary, "cfg", analysis_result)

        result = cache.get(sample_binary, "cfg")
        expect(result == analysis_result)
        expect(cache.get_stats().hits == 1)

    def test_set_with_options(self, cache, sample_binary):
        options = {"depth": 2, "analyze_loops": True}
        cache.set(sample_binary, "cfg", {"data": 1}, options=options)

        result = cache.get(sample_binary, "cfg", options=options)
        expect(result == {"data": 1})

    def test_different_options_different_cache(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"v": 1}, options={"opt": "a"})
        cache.set(sample_binary, "cfg", {"v": 2}, options={"opt": "b"})

        result_a = cache.get(sample_binary, "cfg", options={"opt": "a"})
        result_b = cache.get(sample_binary, "cfg", options={"opt": "b"})

        expect(result_a == {"v": 1})
        expect(result_b == {"v": 2})

    def test_invalidate_all_for_binary(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"data": 1})
        cache.set(sample_binary, "call_graph", {"data": 2})

        removed = cache.invalidate(sample_binary)
        expect(removed == _EXPECTED_REMOVED_2)

        expect(not (cache.get(sample_binary, "cfg") is not None))
        expect(not (cache.get(sample_binary, "call_graph") is not None))

    def test_invalidate_specific_analysis(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"data": 1})
        cache.set(sample_binary, "call_graph", {"data": 2})

        removed = cache.invalidate(sample_binary, analysis_type="cfg")
        expect(removed == 1)

        expect(not (cache.get(sample_binary, "cfg") is not None))
        expect(cache.get(sample_binary, "call_graph") is not None)

    def test_clear(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"data": 1})
        cache.set(sample_binary, "call_graph", {"data": 2})

        removed = cache.clear()
        expect(removed == _EXPECTED_REMOVED_2_2)

        stats = cache.get_stats()
        expect(stats.entry_count == 0)

    def test_size_limit(self, temp_cache_dir, sample_binary):
        cache = AnalysisCache(cache_dir=temp_cache_dir, max_size_mb=0.001)

        for i in range(100):
            cache.set(sample_binary, f"analysis_{i}", {"data": "x" * 100})

        stats = cache.refresh_stats()
        # Allow up to 2x the configured limit since eviction is best-effort
        expect(not (stats.total_size_bytes > _EXPECTED_STATS_TOTAL_SIZE_BYTES_2048))

    def test_get_entry_metadata(self, cache, sample_binary):
        cache.set(
            sample_binary,
            "cfg",
            {"data": 1},
            metadata={"source": "test", "version": "1.0"},
        )

        metadata = cache.get_entry_metadata(sample_binary, "cfg")
        expect(metadata is not None)
        expect(metadata["metadata"]["source"] == "test")
        expect(not ("created_at" not in metadata))

    def test_list_entries(self, cache, sample_binary):
        cache.set(sample_binary, "cfg", {"data": 1})
        cache.set(sample_binary, "call_graph", {"data": 2})

        entries = cache.list_entries()
        expect(len(entries) == _EXPECTED_LEN_ENTRIES_2)

        cfg_entries = cache.list_entries(analysis_type="cfg")
        expect(len(cfg_entries) == 1)
        expect(cfg_entries[0]["analysis_type"] == "cfg")

    def test_cache_with_metadata(self, cache, sample_binary):
        metadata = {"source": "unit_test", "regions": [{"offset": 0, "size": 100}]}
        cache.set(sample_binary, "cfg", {"data": 1}, metadata=metadata)

        result_metadata = cache.get_entry_metadata(sample_binary, "cfg")
        expect(result_metadata["metadata"]["source"] == "unit_test")


class TestCacheStorage:
    @pytest.fixture
    def temp_storage_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_structured_storage_save_load(self, temp_storage_dir):
        storage = CacheStorage(cache_dir=temp_storage_dir)

        storage.save("test_key", {"data": [1, 2, 3]})
        loaded = storage.load("test_key")

        expect(loaded == {"data": [1, 2, 3]})

    def test_storage_exists(self, temp_storage_dir):
        storage = CacheStorage(cache_dir=temp_storage_dir)

        storage.save("test_key", "data")
        expect(storage.exists("test_key"))
        expect(not (storage.exists("nonexistent")))

    def test_storage_delete(self, temp_storage_dir):
        storage = CacheStorage(cache_dir=temp_storage_dir)

        storage.save("test_key", "data")
        expect(storage.delete("test_key"))
        expect(not (storage.exists("test_key")))
        expect(not (storage.delete("nonexistent")))

    def test_storage_none_cache_dir(self):
        storage = CacheStorage(cache_dir=None)

        storage.save("test_key", "data")
        expect(not (storage.load("test_key") is not None))
        expect(not (storage.exists("test_key")))


class TestHashing:
    @pytest.fixture
    def temp_binary(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            yield Path(f.name)

    def test_compute_binary_hash(self, temp_binary):
        hash1 = compute_binary_hash(temp_binary)
        hash2 = compute_binary_hash(temp_binary)

        expect(hash1 == hash2)
        expect(len(hash1) == _EXPECTED_LEN_HASH1_64)

    def test_compute_partial_hash(self, temp_binary):
        hash1 = compute_partial_hash(temp_binary, 0, 50)
        hash2 = compute_partial_hash(temp_binary, 0, 50)

        expect(hash1 == hash2)
        expect(len(hash1) == _EXPECTED_LEN_HASH1_32)

    def test_different_files_different_hash(self, temp_binary):
        hash1 = compute_binary_hash(temp_binary)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"a" * 200)
            other_path = Path(f.name)

        hash2 = compute_binary_hash(other_path)
        expect(hash1 != hash2)
        other_path.unlink(missing_ok=True)

    def test_binary_hash_stability(self, temp_binary):
        hashes = [compute_binary_hash(temp_binary) for _ in range(5)]
        expect(all(h == hashes[0] for h in hashes))


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
        expect(cached == cfg_result)
        expect(cached["blocks"][0]["address"] == _EXPECTED_CACHED_BLOCKS_0_ADDRESS_4096)

    def test_simulated_multiple_analyses(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir)
        binary = b"BINARY_DATA"

        cache.set(binary, "cfg", {"blocks": [1, 2]})
        cache.set(binary, "call_graph", {"nodes": [1, 2, 3]})
        cache.set(binary, "type_inference", {"types": ["int", "ptr"]})

        expect(cache.get(binary, "cfg") == {"blocks": [1, 2]})
        expect(cache.get(binary, "call_graph") == {"nodes": [1, 2, 3]})
        expect(cache.get(binary, "type_inference") == {"types": ["int", "ptr"]})

    def test_persistence_across_instances(self, temp_cache_dir):
        binary = b"BINARY_DATA"

        cache1 = AnalysisCache(cache_dir=temp_cache_dir)
        cache1.set(binary, "cfg", {"persistent": "data"})

        cache2 = AnalysisCache(cache_dir=temp_cache_dir)
        result = cache2.get(binary, "cfg")

        expect(result == {"persistent": "data"})

    def test_stats_tracking(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir)
        binary = b"BINARY_DATA"

        cache.get(binary, "cfg")
        cache.set(binary, "cfg", {"data": 1})
        cache.get(binary, "cfg")
        cache.get(binary, "cfg")

        stats = cache.get_stats()
        expect(stats.misses == 1)
        expect(stats.hits == _EXPECTED_STATS_HITS_2)
        expect(stats.hit_rate == 2 / 3)


class TestBackgroundCleanup:
    @pytest.fixture
    def temp_cache_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_cleanup_expired_removes_old_entries(self, temp_cache_dir):
        timedelta = importlib.import_module("datetime").timedelta

        cache_entry = importlib.import_module("r2morph.core.analysis_cache").CacheEntry

        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        binary = b"BINARY_DATA"

        cache.set(binary, "cfg", {"data": 1})

        key = CacheKey(
            binary_hash=cache._hash_binary(binary),
            analysis_type="cfg",
            options_hash=cache._hash_options({}),
        )
        old_entry = cache_entry(key=key, data={"data": 2})
        old_entry.created_at = datetime.now() - timedelta(days=100)
        old_entry.accessed_at = datetime.now() - timedelta(days=100)
        cache._save_entry(old_entry)

        removed = cache.cleanup_expired(max_age_days=30)
        expect(removed == 1)

    def test_cleanup_expired_keeps_recent(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        binary = b"BINARY_DATA"

        cache.set(binary, "cfg", {"data": 1})

        removed = cache.cleanup_expired(max_age_days=30)
        expect(removed == 0)

        result = cache.get(binary, "cfg")
        expect(result == {"data": 1})

    def test_cleanup_low_access_removes_unused(self, temp_cache_dir):
        timedelta = importlib.import_module("datetime").timedelta

        cache_entry = importlib.import_module("r2morph.core.analysis_cache").CacheEntry

        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        binary = b"BINARY_DATA"

        key = CacheKey(
            binary_hash=cache._hash_binary(binary),
            analysis_type="cfg",
            options_hash=cache._hash_options({}),
        )
        old_entry = cache_entry(key=key, data={"data": 1})
        old_entry.created_at = datetime.now() - timedelta(days=100)
        old_entry.accessed_at = datetime.now() - timedelta(days=100)
        cache._save_entry(old_entry)

        removed = cache.cleanup_low_access(min_access_count=2, max_age_days=7)
        expect(removed == 1)

    def test_cleanup_low_access_keeps_frequently_accessed(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        binary = b"BINARY_DATA"

        cache.set(binary, "cfg", {"data": 1})
        cache.get(binary, "cfg")
        cache.get(binary, "cfg")

        removed = cache.cleanup_low_access(min_access_count=2, max_age_days=0)
        expect(removed == 0)

        result = cache.get(binary, "cfg")
        expect(result == {"data": 1})

    def test_background_cleanup_disabled(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=False)
        expect(not (cache._cleanup_thread is not None))

    def test_background_cleanup_enabled(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=True)
        expect(cache._cleanup_thread is not None)
        expect(cache._cleanup_thread.is_alive())

        cache.stop_cleanup_thread()
        expect(not (cache._cleanup_thread.is_alive()))

    def test_stop_cleanup_thread(self, temp_cache_dir):
        cache = AnalysisCache(cache_dir=temp_cache_dir, enable_background_cleanup=True)

        expect(cache._cleanup_thread.is_alive())
        cache.stop_cleanup_thread()

        time = importlib.import_module("time")

        time.sleep(0.1)
        expect(not (cache._cleanup_thread.is_alive()))

    def test_cleanup_with_custom_interval(self, temp_cache_dir):
        cache = AnalysisCache(
            cache_dir=temp_cache_dir,
            cleanup_interval_seconds=60,
            enable_background_cleanup=True,
        )
        expect(cache.cleanup_interval_seconds == _EXPECTED_CACHE_CLEANUP_INTERVAL_SECONDS_60)

        cache.stop_cleanup_thread()
