from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier, SimplificationStrategy


def test_iterative_simplifier_complexity_and_checkpoint():
    simplifier = IterativeSimplifier()
    context = {
        "functions": [1, 2, 3],
        "obfuscation_patterns": ["a"],
        "mba_expressions": ["x ^ y"],
        "vm_dispatchers": [0x1000],
    }
    complexity = simplifier._calculate_complexity(context)
    assert complexity == 3 + 1 + 1 + 10

    checkpoint = simplifier._create_checkpoint(context)
    assert checkpoint["context"]["functions"] == [1, 2, 3]


def test_iterative_simplifier_strategy_adjustment_and_validation():
    simplifier = IterativeSimplifier()
    simplifier.strategy = SimplificationStrategy.ADAPTIVE
    initial_threshold = simplifier.convergence_threshold

    simplifier._adjust_strategy(0.04, iteration=1)
    assert simplifier.convergence_threshold >= initial_threshold

    simplifier.metrics.complexity_reduction = 0.0
    validation = simplifier._validate_result({"errors": ["fail"]})
    assert validation["warnings"]
