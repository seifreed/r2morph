"""Named constants for r2morph to replace magic numbers."""

# Binary size thresholds (in megabytes)
LARGE_BINARY_THRESHOLD_MB = 50
VERY_LARGE_BINARY_THRESHOLD_MB = 100

# Function filtering
MINIMUM_FUNCTION_SIZE = 10
SMALL_FUNCTION_THRESHOLD = 50
OPAQUE_PREDICATE_MIN_FUNCTION_SIZE = 20

# Batch processing
BATCH_MUTATION_CHECKPOINT = 1000

# Analysis thresholds (function counts)
MEDIUM_FUNCTION_COUNT_THRESHOLD = 2000
LARGE_FUNCTION_COUNT_THRESHOLD = 3000
MANY_FUNCTIONS_THRESHOLD = 5000
VERY_MANY_FUNCTIONS_THRESHOLD = 10000

# Entropy thresholds
HIGH_ENTROPY_THRESHOLD = 7.0
PACKED_ENTROPY_THRESHOLD = 7.5

# Instruction size estimation
AVG_INSTRUCTION_SIZE_BYTES = 4

# Severity ranking
# SEVERITY_ORDER maps known severities to ascending ranks (lower = more
# severe). UNKNOWN_SEVERITY_RANK is the sentinel rank for an
# unknown/unrecognized severity; it sorts after every known one.
SEVERITY_ORDER: dict[str, int] = {
    "mismatch": 0,
    "without-coverage": 1,
    "bounded-only": 2,
    "clean": 3,
    "not-requested": 4,
}
# IMPACT_SEVERITY_ORDER ranks discarded-mutation impact severities (lower =
# higher impact). These keys are disjoint from SEVERITY_ORDER, which ranks
# symbolic/validation outcomes; do not conflate the two.
IMPACT_SEVERITY_ORDER: dict[str, int] = {
    "high": 0,
    "medium": 1,
    "low": 2,
}
UNKNOWN_SEVERITY_RANK = 99

# Analysis cache defaults
ANALYSIS_CACHE_MAX_SIZE_MB = 500
ANALYSIS_CACHE_MAX_AGE_DAYS = 30
ANALYSIS_CACHE_CLEANUP_INTERVAL_SECONDS = 3600

# Control flow transfer instructions (unconditional)
UNCONDITIONAL_TRANSFERS = frozenset({"jmp", "ret", "retn", "b", "br", "bx", "blr"})
