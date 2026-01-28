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

# Control flow transfer instructions (unconditional)
UNCONDITIONAL_TRANSFERS = frozenset({"jmp", "ret", "retn", "b", "br", "bx", "blr"})
