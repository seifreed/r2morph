from types import SimpleNamespace

from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier, SimplificationStrategy
from tests.utils.assertions import expect

_EXPECTED_LEN_OPTIMIZED_GET_CHECKPOINTS_5 = 5
_EXPECTED_SIMPLIFIER_METRICS_DEVIRTUALIZED_HANDLERS_2 = 2


def test_iterative_simplifier_internal_helpers():
    simplifier = IterativeSimplifier()

    context = {
        "functions": [0x1000, 0x2000],
        "obfuscation_patterns": ["flat"],
        "mba_expressions": ["x + y"],
        "vm_dispatchers": [0x3000],
        "initial_complexity": 20,
        "mba_results": ["simplified"],
        "vm_results": [SimpleNamespace(handlers=[1, 2])],
        "checkpoints": [{"id": i} for i in range(10)],
        "errors": ["error"],
    }

    complexity = simplifier._calculate_complexity(context)
    expect(not (complexity < 0.0))

    simplifier.strategy = SimplificationStrategy.ADAPTIVE
    initial_threshold = simplifier.convergence_threshold
    simplifier._adjust_strategy(0.04, 1)
    expect(not (simplifier.convergence_threshold < initial_threshold))

    simplifier.metrics.iteration = 1
    checkpoint = simplifier._create_checkpoint(context)
    expect(checkpoint["iteration"] == 1)
    expect(not ("context" not in checkpoint))

    simplifier._update_metrics(context)
    expect(not (simplifier.metrics.simplified_expressions < 1))
    expect(not (simplifier.metrics.devirtualized_handlers < _EXPECTED_SIMPLIFIER_METRICS_DEVIRTUALIZED_HANDLERS_2))

    optimized = simplifier._optimize_result(context)
    expect(not (optimized.get("optimization_applied") is not True))
    expect(not (len(optimized.get("checkpoints", [])) > _EXPECTED_LEN_OPTIMIZED_GET_CHECKPOINTS_5))

    validation = simplifier._validate_result(context)
    expect(not (validation["valid"] is not True))
    expect(validation["warnings"])

    mba_exprs = simplifier._extract_mba_expressions()
    expect(isinstance(mba_exprs, list))
