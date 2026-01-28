from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier, SimplificationStrategy
from r2morph.devirtualization.vm_handler_analyzer import VMArchitecture, VMHandler


def test_iterative_complexity_and_strategy_adjustment():
    simplifier = IterativeSimplifier(binary=object())
    context = {
        "functions": [1, 2, 3],
        "obfuscation_patterns": ["cfo"],
        "mba_expressions": ["x + y"],
        "vm_dispatchers": [0x1000],
    }

    complexity = simplifier._calculate_complexity(context)
    assert complexity == 3 + 1 + 1 + 10

    simplifier.strategy = SimplificationStrategy.ADAPTIVE
    simplifier.convergence_threshold = 0.01
    simplifier._adjust_strategy(improvement=0.04, iteration=1)
    assert 0.01 < simplifier.convergence_threshold <= 0.02


def test_iterative_checkpoint_rollback_and_progress_report():
    simplifier = IterativeSimplifier(binary=object())
    simplifier.metrics.iteration = 3
    context = {"functions": [1]}

    checkpoint = simplifier._create_checkpoint(context)
    simplifier.checkpoints.append(checkpoint)

    simplifier.metrics.iteration = 7
    assert simplifier.rollback_to_checkpoint() is True
    assert simplifier.metrics is checkpoint["metrics"]

    report = simplifier.get_progress_report()
    assert report["iteration"] == simplifier.metrics.iteration
    assert report["checkpoints"] == 1


def test_iterative_update_metrics_and_reduction():
    simplifier = IterativeSimplifier(binary=object())

    vm_arch = VMArchitecture(
        dispatcher_address=0x1000,
        handlers={
            1: VMHandler(handler_id=1, entry_address=0x2000, size=4),
            2: VMHandler(handler_id=2, entry_address=0x2010, size=4),
        },
    )

    context = {
        "initial_complexity": 5,
        "functions": [1, 2],
        "obfuscation_patterns": [],
        "mba_expressions": [],
        "vm_dispatchers": [],
        "mba_results": ["simplified"],
        "vm_results": [vm_arch],
    }

    simplifier._update_metrics(context)
    assert simplifier.metrics.simplified_expressions == 1
    assert simplifier.metrics.devirtualized_handlers == 2
    assert simplifier.metrics.complexity_reduction > 0
