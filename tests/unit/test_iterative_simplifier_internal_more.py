from types import SimpleNamespace

from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier, SimplificationStrategy


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
    assert complexity >= 0.0

    simplifier.strategy = SimplificationStrategy.ADAPTIVE
    initial_threshold = simplifier.convergence_threshold
    simplifier._adjust_strategy(0.04, 1)
    assert simplifier.convergence_threshold >= initial_threshold

    simplifier.metrics.iteration = 1
    checkpoint = simplifier._create_checkpoint(context)
    assert checkpoint["iteration"] == 1
    assert "context" in checkpoint

    simplifier._update_metrics(context)
    assert simplifier.metrics.simplified_expressions >= 1
    assert simplifier.metrics.devirtualized_handlers >= 2

    optimized = simplifier._optimize_result(context)
    assert optimized.get("optimization_applied") is True
    assert len(optimized.get("checkpoints", [])) <= 5

    validation = simplifier._validate_result(context)
    assert validation["valid"] is True
    assert validation["warnings"]

    mba_exprs = simplifier._extract_mba_expressions()
    assert "x + y" in mba_exprs
