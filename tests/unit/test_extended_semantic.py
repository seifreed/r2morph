"""
Unit tests for extended semantic validation module.
"""

from r2morph.analysis.cfg import BasicBlock, BlockType, ControlFlowGraph
from r2morph.validation.extended_semantic import (
    ConstraintCache,
    ConstraintCacheEntry,
    ExtendedSemanticConfig,
    ExtendedSemanticValidator,
    ImprovedStateMerging,
    ValidationResult,
    create_extended_validator,
)
from r2morph.validation.semantic import ValidationMode


class _Binary:
    path = "/tmp/test"

    def get_arch_info(self) -> dict[str, object]:
        return {"arch": "x86", "bits": 64}

    def get_functions(self) -> list[dict[str, object]]:
        return []


class TestConstraintCache:
    """Tests for ConstraintCache class."""

    def test_cache_creation(self):
        """Test cache creation."""
        cache = ConstraintCache()
        assert cache.max_size == 10000
        assert cache.ttl_seconds == 3600
        assert len(cache._cache) == 0

    def test_cache_creation_with_params(self):
        """Test cache creation with custom parameters."""
        cache = ConstraintCache(max_size=5000, ttl_seconds=1800)
        assert cache.max_size == 5000
        assert cache.ttl_seconds == 1800

    def test_cache_set_and_get(self):
        """Test setting and getting cache entries."""
        cache = ConstraintCache()

        constraint = object()
        result = object()

        cache.set(constraint, result, is_satisfiable=True)

        entry = cache.get(constraint)
        assert entry is not None
        assert entry.is_satisfiable is True
        assert entry.hit_count == 1

    def test_cache_hits_and_misses(self):
        """Test cache hit/miss tracking."""
        cache = ConstraintCache()

        constraint = object()
        result = object()

        cache.set(constraint, result, is_satisfiable=True)

        for _ in range(3):
            cache.get(constraint)

        assert cache._hits == 3

        other_constraint = object()
        cache.get(other_constraint)
        assert cache._misses == 1

    def test_cache_hit_rate(self):
        """Test hit rate calculation."""
        cache = ConstraintCache()

        cache._hits = 80
        cache._misses = 20

        assert cache.get_hit_rate() == 0.8

    def test_cache_hit_rate_empty(self):
        """Test hit rate with no accesses."""
        cache = ConstraintCache()
        assert cache.get_hit_rate() == 0.0

    def test_cache_clear(self):
        """Test cache clearing."""
        cache = ConstraintCache()

        constraint = object()
        cache.set(constraint, object(), is_satisfiable=True)

        assert len(cache._cache) == 1

        cache.clear()
        assert len(cache._cache) == 0
        assert cache._hits == 0
        assert cache._misses == 0

    def test_cache_statistics(self):
        """Test cache statistics."""
        cache = ConstraintCache(max_size=5000)

        stats = cache.get_statistics()

        assert "entries" in stats
        assert "max_size" in stats
        assert "hits" in stats
        assert "misses" in stats
        assert "hit_rate" in stats
        assert stats["max_size"] == 5000

    def test_cache_invalidate(self):
        """Test cache invalidation."""
        cache = ConstraintCache()

        constraint = object()
        cache.set(constraint, object(), is_satisfiable=True)

        assert len(cache._cache) == 1

        cache.invalidate(0x1000)

        assert cache.get(constraint) is not None

    def test_cache_eviction(self):
        """Test cache eviction when full."""
        cache = ConstraintCache(max_size=10)

        for i in range(15):
            constraint = f"constraint-{i}"
            cache.set(constraint, object(), is_satisfiable=True)

        assert len(cache._cache) <= cache.max_size


class TestImprovedStateMerging:
    """Tests for ImprovedStateMerging class."""

    def test_merger_creation(self):
        """Test merger creation."""
        merger = ImprovedStateMerging()
        assert merger.k_limit == 3
        assert len(merger._merge_points) == 0

    def test_merger_creation_with_params(self):
        """Test merger with custom k_limit."""
        merger = ImprovedStateMerging(k_limit=5)
        assert merger.k_limit == 5

    def test_find_merge_points(self):
        """Test finding merge points in CFG."""
        merger = ImprovedStateMerging()

        cfg = ControlFlowGraph(function_address=0x1000, function_name="test")

        entry = BasicBlock(
            address=0x1000,
            size=8,
            instructions=[],
            successors=[0x1010, 0x1020],
            predecessors=[],
            block_type=BlockType.ENTRY,
        )

        left = BasicBlock(
            address=0x1010,
            size=4,
            instructions=[],
            successors=[0x1030],
            predecessors=[0x1000],
            block_type=BlockType.NORMAL,
        )

        right = BasicBlock(
            address=0x1020,
            size=4,
            instructions=[],
            successors=[0x1030],
            predecessors=[0x1000],
            block_type=BlockType.NORMAL,
        )

        merge = BasicBlock(
            address=0x1030,
            size=4,
            instructions=[],
            successors=[],
            predecessors=[0x1010, 0x1020],
            block_type=BlockType.RETURN,
        )

        cfg.add_block(entry)
        cfg.add_block(left)
        cfg.add_block(right)
        cfg.add_block(merge)
        cfg.add_edge(0x1000, 0x1010)
        cfg.add_edge(0x1000, 0x1020)
        cfg.add_edge(0x1010, 0x1030)
        cfg.add_edge(0x1020, 0x1030)

        merge_points = merger.find_merge_points(cfg)

        assert 0x1030 in merge_points

    def test_get_merge_statistics(self):
        """Test getting merge statistics."""
        merger = ImprovedStateMerging()

        stats = merger.get_merge_statistics()

        assert "merge_points" in stats
        assert "states_at_merge_points" in stats


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_result_creation(self):
        """Test result creation."""
        result = ValidationResult(
            is_valid=True,
            message="Validation passed",
        )

        assert result.is_valid is True
        assert result.message == "Validation passed"
        assert result.execution_time == 0.0
        assert result.cache_hits == 0

    def test_result_with_details(self):
        """Test result with details."""
        result = ValidationResult(
            is_valid=False,
            message="Validation failed",
            details={"error": "constraint_unsatisfied"},
            execution_time=1.5,
            cache_hits=10,
            cache_misses=5,
        )

        assert result.is_valid is False
        assert "error" in result.details
        assert result.execution_time == 1.5
        assert result.cache_hits == 10


class TestExtendedSemanticValidator:
    """Tests for ExtendedSemanticValidator class."""

    def test_validator_creation(self):
        """Test validator creation."""
        validator = ExtendedSemanticValidator(_Binary())

        assert validator.max_states == 10000
        assert validator.max_steps == 500
        assert validator.use_constraint_cache is True
        assert validator.merge_interval == 100
        assert validator._constraint_cache is not None

    def test_validator_creation_no_cache(self):
        """Test validator without cache."""
        validator = ExtendedSemanticValidator(_Binary(), config=ExtendedSemanticConfig(use_constraint_cache=False))

        assert validator._constraint_cache is None

    def test_validator_thorough_mode(self):
        """Test validator in thorough mode."""
        validator = ExtendedSemanticValidator(
            _Binary(),
            mode=ValidationMode.THOROUGH,
        )

        assert validator.max_states == 10000
        assert validator.max_steps == 500

    def test_validate_function_semantics(self):
        """Test function semantic validation."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_function_semantics(0x1000)

        assert result.region.function_address == 0x1000
        assert result.region.pass_name == "function_semantic_validation"

    def test_validate_loop_semantics(self):
        """Test loop semantic validation."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_loop_semantics(0x1000, 0x1100, max_iterations=5)

        assert "loop_start" in result.details
        assert "loop_end" in result.details
        assert result.details["loop_start"] == "0x1000"
        assert result.details["loop_end"] == "0x1100"

    def test_validate_call_chain(self):
        """Test call chain validation."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_call_chain([0x1000, 0x1100, 0x1200])

        assert result.is_valid is True
        assert "chain_length" in result.details
        assert result.details["chain_length"] == 3

    def test_validate_call_chain_empty(self):
        """Test empty call chain validation."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_call_chain([])

        assert result.is_valid is False
        assert "empty" in result.message.lower()

    def test_clear_cache(self):
        """Test cache clearing."""
        validator = ExtendedSemanticValidator(_Binary())

        validator._constraint_cache._hits = 10

        validator.clear_cache()

        assert validator._constraint_cache._hits == 0
        assert len(validator._validation_cache) == 0

    def test_get_cache_statistics(self):
        """Test getting cache statistics."""
        validator = ExtendedSemanticValidator(_Binary())

        stats = validator.get_cache_statistics()

        assert "validation_cache_size" in stats
        assert "constraint_cache" in stats

    def test_validator_reports_symbolic_availability(self):
        """Test validator reports the symbolic backend state."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_function_semantics(0x1000)

        assert result.symbolic_status in {"not_requested", "angr_unavailable"} or result.symbolic_status.startswith(
            "error:"
        )


class TestCreateExtendedValidator:
    """Tests for create_extended_validator function."""

    def test_create_standard_mode(self):
        """Test creating validator in standard mode."""
        validator = create_extended_validator(_Binary(), mode="standard")

        assert validator.mode == ValidationMode.STANDARD
        assert validator.max_states == 5000
        assert validator.max_steps == 250

    def test_create_thorough_mode(self):
        """Test creating validator in thorough mode."""
        validator = create_extended_validator(_Binary(), mode="thorough")

        assert validator.mode == ValidationMode.THOROUGH
        assert validator.max_states == 10000
        assert validator.max_steps == 500

    def test_create_fast_mode(self):
        """Test creating validator in fast mode."""
        validator = create_extended_validator(_Binary(), mode="fast")

        assert validator.mode == ValidationMode.FAST
        assert validator.max_states == 1000
        assert validator.max_steps == 100

    def test_create_with_custom_params(self):
        """Test creating validator with custom parameters."""
        validator = create_extended_validator(
            _Binary(),
            mode="standard",
            max_states=2000,
            max_steps=300,
        )

        assert validator.max_states == 2000
        assert validator.max_steps == 300


class TestConstraintCacheEntry:
    """Tests for ConstraintCacheEntry class."""

    def test_entry_creation(self):
        """Test entry creation."""
        entry = ConstraintCacheEntry(
            constraint_hash=12345,
            result=object(),
            is_satisfiable=True,
            timestamp=100.0,
        )

        assert entry.constraint_hash == 12345
        assert entry.is_satisfiable is True
        assert entry.hit_count == 0

    def test_entry_hit_count(self):
        """Test entry hit count tracking."""
        entry = ConstraintCacheEntry(
            constraint_hash=12345,
            result=object(),
            is_satisfiable=True,
            timestamp=100.0,
        )

        entry.hit_count += 1
        entry.hit_count += 1

        assert entry.hit_count == 2
