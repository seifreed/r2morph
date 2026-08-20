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
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

_EXPECTED_CACHE_GET_HIT_RATE_0_8 = 0.8
_EXPECTED_CACHE_HITS_3 = 3
_EXPECTED_CACHE_MAX_SIZE_10000 = 10000
_EXPECTED_CACHE_MAX_SIZE_5000 = 5000
_EXPECTED_CACHE_TTL_SECONDS_1800 = 1800
_EXPECTED_CACHE_TTL_SECONDS_3600 = 3600
_EXPECTED_ENTRY_CONSTRAINT_HASH_12345 = 12345
_EXPECTED_ENTRY_HIT_COUNT_2 = 2
_EXPECTED_MERGER_K_LIMIT_3 = 3
_EXPECTED_MERGER_K_LIMIT_5 = 5
_EXPECTED_MERGE_POINTS_4144 = 0x1030
_EXPECTED_RESULT_CACHE_HITS_10 = 10
_EXPECTED_RESULT_DETAILS_CHAIN_LENGTH_3 = 3
_EXPECTED_RESULT_EXECUTION_TIME_1_5 = 1.5
_EXPECTED_RESULT_REGION_FUNCTION_ADDRESS_4096 = 0x1000
_EXPECTED_STATS_MAX_SIZE_5000 = 5000
_EXPECTED_VALIDATOR_MAX_STATES_1000 = 1000
_EXPECTED_VALIDATOR_MAX_STATES_10000 = 10000
_EXPECTED_VALIDATOR_MAX_STATES_10000_2 = 10000
_EXPECTED_VALIDATOR_MAX_STATES_10000_3 = 10000
_EXPECTED_VALIDATOR_MAX_STATES_2000 = 2000
_EXPECTED_VALIDATOR_MAX_STATES_5000 = 5000
_EXPECTED_VALIDATOR_MAX_STEPS_100 = 100
_EXPECTED_VALIDATOR_MAX_STEPS_250 = 250
_EXPECTED_VALIDATOR_MAX_STEPS_300 = 300
_EXPECTED_VALIDATOR_MAX_STEPS_500 = 500
_EXPECTED_VALIDATOR_MAX_STEPS_500_2 = 500
_EXPECTED_VALIDATOR_MAX_STEPS_500_3 = 500
_EXPECTED_VALIDATOR_MERGE_INTERVAL_100 = 100


class _Binary:
    path = "test-data/test"

    def get_arch_info(self) -> dict[str, object]:
        return {"arch": "x86", "bits": 64}

    def get_functions(self) -> list[dict[str, object]]:
        return []


class TestConstraintCache:
    """Tests for ConstraintCache class."""

    def test_cache_creation(self):
        """Test cache creation."""
        cache = ConstraintCache()
        expect(cache.max_size == _EXPECTED_CACHE_MAX_SIZE_10000)
        expect(cache.ttl_seconds == _EXPECTED_CACHE_TTL_SECONDS_3600)
        expect(len(cache._cache) == 0)

    def test_cache_creation_with_params(self):
        """Test cache creation with custom parameters."""
        cache = ConstraintCache(max_size=5000, ttl_seconds=1800)
        expect(cache.max_size == _EXPECTED_CACHE_MAX_SIZE_5000)
        expect(cache.ttl_seconds == _EXPECTED_CACHE_TTL_SECONDS_1800)

    def test_cache_set_and_get(self):
        """Test setting and getting cache entries."""
        cache = ConstraintCache()

        constraint = object()
        result = object()

        cache.set(constraint, result, is_satisfiable=True)

        entry = cache.get(constraint)
        expect(entry is not None)
        expect(not (entry.is_satisfiable is not True))
        expect(entry.hit_count == 1)

    def test_cache_hits_and_misses(self):
        """Test cache hit/miss tracking."""
        cache = ConstraintCache()

        constraint = object()
        result = object()

        cache.set(constraint, result, is_satisfiable=True)

        for _ in range(3):
            cache.get(constraint)

        expect(cache._hits == _EXPECTED_CACHE_HITS_3)

        other_constraint = object()
        cache.get(other_constraint)
        expect(cache._misses == 1)

    def test_cache_hit_rate(self):
        """Test hit rate calculation."""
        cache = ConstraintCache()

        cache._hits = 80
        cache._misses = 20

        expect(cache.get_hit_rate() == _EXPECTED_CACHE_GET_HIT_RATE_0_8)

    def test_cache_hit_rate_empty(self):
        """Test hit rate with no accesses."""
        cache = ConstraintCache()
        expect(cache.get_hit_rate() == 0.0)

    def test_cache_clear(self):
        """Test cache clearing."""
        cache = ConstraintCache()

        constraint = object()
        cache.set(constraint, object(), is_satisfiable=True)

        expect(len(cache._cache) == 1)

        cache.clear()
        expect(len(cache._cache) == 0)
        expect(cache._hits == 0)
        expect(cache._misses == 0)

    def test_cache_statistics(self):
        """Test cache statistics."""
        cache = ConstraintCache(max_size=5000)

        stats = cache.get_statistics()

        expect(not ("entries" not in stats))
        expect(not ("max_size" not in stats))
        expect(not ("hits" not in stats))
        expect(not ("misses" not in stats))
        expect(not ("hit_rate" not in stats))
        expect(stats["max_size"] == _EXPECTED_STATS_MAX_SIZE_5000)

    def test_cache_invalidate(self):
        """Test cache invalidation."""
        cache = ConstraintCache()

        constraint = object()
        cache.set(constraint, object(), is_satisfiable=True)

        expect(len(cache._cache) == 1)

        cache.invalidate(0x1000)

        expect(cache.get(constraint) is not None)

    def test_cache_eviction(self):
        """Test cache eviction when full."""
        cache = ConstraintCache(max_size=10)

        for i in range(15):
            constraint = f"constraint-{i}"
            cache.set(constraint, object(), is_satisfiable=True)

        expect(not (len(cache._cache) > cache.max_size))


class TestImprovedStateMerging:
    """Tests for ImprovedStateMerging class."""

    def test_merger_creation(self):
        """Test merger creation."""
        merger = ImprovedStateMerging()
        expect(merger.k_limit == _EXPECTED_MERGER_K_LIMIT_3)
        expect(len(merger._merge_points) == 0)

    def test_merger_creation_with_params(self):
        """Test merger with custom k_limit."""
        merger = ImprovedStateMerging(k_limit=5)
        expect(merger.k_limit == _EXPECTED_MERGER_K_LIMIT_5)

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

        expect(not (_EXPECTED_MERGE_POINTS_4144 not in merge_points))

    def test_get_merge_statistics(self):
        """Test getting merge statistics."""
        merger = ImprovedStateMerging()

        stats = merger.get_merge_statistics()

        expect(not ("merge_points" not in stats))
        expect(not ("states_at_merge_points" not in stats))


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_result_creation(self):
        """Test result creation."""
        result = ValidationResult(
            is_valid=True,
            message="Validation passed",
        )

        expect(not (result.is_valid is not True))
        expect(result.message == "Validation passed")
        expect(result.execution_time == 0.0)
        expect(result.cache_hits == 0)

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

        expect(not (result.is_valid is not False))
        expect(not ("error" not in result.details))
        expect(result.execution_time == _EXPECTED_RESULT_EXECUTION_TIME_1_5)
        expect(result.cache_hits == _EXPECTED_RESULT_CACHE_HITS_10)


class TestExtendedSemanticValidator:
    """Tests for ExtendedSemanticValidator class."""

    def test_validator_creation(self):
        """Test validator creation."""
        validator = ExtendedSemanticValidator(_Binary())

        expect(validator.max_states == _EXPECTED_VALIDATOR_MAX_STATES_10000)
        expect(validator.max_steps == _EXPECTED_VALIDATOR_MAX_STEPS_500)
        expect(not (validator.use_constraint_cache is not True))
        expect(validator.merge_interval == _EXPECTED_VALIDATOR_MERGE_INTERVAL_100)
        expect(validator._constraint_cache is not None)

    def test_validator_creation_no_cache(self):
        """Test validator without cache."""
        validator = ExtendedSemanticValidator(_Binary(), config=ExtendedSemanticConfig(use_constraint_cache=False))

        expect(not (validator._constraint_cache is not None))

    def test_validator_thorough_mode(self):
        """Test validator in thorough mode."""
        validator = ExtendedSemanticValidator(
            _Binary(),
            mode=ValidationMode.THOROUGH,
        )

        expect(validator.max_states == _EXPECTED_VALIDATOR_MAX_STATES_10000_2)
        expect(validator.max_steps == _EXPECTED_VALIDATOR_MAX_STEPS_500_2)

    def test_validate_function_semantics(self):
        """Test function semantic validation."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_function_semantics(0x1000)

        expect(result.region.function_address == _EXPECTED_RESULT_REGION_FUNCTION_ADDRESS_4096)
        expect(getattr(result.region, MUTATION_NAME_KEY) == "function_semantic_validation")

    def test_validate_loop_semantics(self):
        """Test loop semantic validation."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_loop_semantics(0x1000, 0x1100, max_iterations=5)

        expect(not ("loop_start" not in result.details))
        expect(not ("loop_end" not in result.details))
        expect(result.details["loop_start"] == "0x1000")
        expect(result.details["loop_end"] == "0x1100")

    def test_validate_call_chain(self):
        """Test call chain validation."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_call_chain([0x1000, 0x1100, 0x1200])

        expect(not (result.is_valid is not True))
        expect(not ("chain_length" not in result.details))
        expect(result.details["chain_length"] == _EXPECTED_RESULT_DETAILS_CHAIN_LENGTH_3)

    def test_validate_call_chain_empty(self):
        """Test empty call chain validation."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_call_chain([])

        expect(not (result.is_valid is not False))
        expect(not ("empty" not in result.message.lower()))

    def test_clear_cache(self):
        """Test cache clearing."""
        validator = ExtendedSemanticValidator(_Binary())

        validator._constraint_cache._hits = 10

        validator.clear_cache()

        expect(validator._constraint_cache._hits == 0)
        expect(len(validator._validation_cache) == 0)

    def test_get_cache_statistics(self):
        """Test getting cache statistics."""
        validator = ExtendedSemanticValidator(_Binary())

        stats = validator.get_cache_statistics()

        expect(not ("validation_cache_size" not in stats))
        expect(not ("constraint_cache" not in stats))

    def test_validator_reports_symbolic_availability(self):
        """Test validator reports the symbolic backend state."""
        validator = ExtendedSemanticValidator(_Binary())

        result = validator.validate_function_semantics(0x1000)

        expect(
            result.symbolic_status in {"not_requested", "angr_unavailable"}
            or result.symbolic_status.startswith("error:")
        )


class TestCreateExtendedValidator:
    """Tests for create_extended_validator function."""

    def test_create_standard_mode(self):
        """Test creating validator in standard mode."""
        validator = create_extended_validator(_Binary(), mode="standard")

        expect(validator.mode == ValidationMode.STANDARD)
        expect(validator.max_states == _EXPECTED_VALIDATOR_MAX_STATES_5000)
        expect(validator.max_steps == _EXPECTED_VALIDATOR_MAX_STEPS_250)

    def test_create_thorough_mode(self):
        """Test creating validator in thorough mode."""
        validator = create_extended_validator(_Binary(), mode="thorough")

        expect(validator.mode == ValidationMode.THOROUGH)
        expect(validator.max_states == _EXPECTED_VALIDATOR_MAX_STATES_10000_3)
        expect(validator.max_steps == _EXPECTED_VALIDATOR_MAX_STEPS_500_3)

    def test_create_fast_mode(self):
        """Test creating validator in fast mode."""
        validator = create_extended_validator(_Binary(), mode="fast")

        expect(validator.mode == ValidationMode.FAST)
        expect(validator.max_states == _EXPECTED_VALIDATOR_MAX_STATES_1000)
        expect(validator.max_steps == _EXPECTED_VALIDATOR_MAX_STEPS_100)

    def test_create_with_custom_params(self):
        """Test creating validator with custom parameters."""
        validator = create_extended_validator(
            _Binary(),
            mode="standard",
            max_states=2000,
            max_steps=300,
        )

        expect(validator.max_states == _EXPECTED_VALIDATOR_MAX_STATES_2000)
        expect(validator.max_steps == _EXPECTED_VALIDATOR_MAX_STEPS_300)


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

        expect(entry.constraint_hash == _EXPECTED_ENTRY_CONSTRAINT_HASH_12345)
        expect(not (entry.is_satisfiable is not True))
        expect(entry.hit_count == 0)

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

        expect(entry.hit_count == _EXPECTED_ENTRY_HIT_COUNT_2)
