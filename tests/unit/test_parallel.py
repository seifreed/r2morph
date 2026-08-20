"""
Tests for parallel mutation execution.
"""

import importlib
from pathlib import Path

from r2morph.core.parallel import (
    DependencyResolver,
    ExecutionPlan,
    ParallelMutationEngine,
    PassDependency,
    PassResult,
    PassStatus,
    execute_parallel,
)
from r2morph.mutations.base import MutationPass
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

_EXPECTED_D_MUTATIONS_APPLIED_3 = 3
_EXPECTED_LEN_PLAN_STAGES_2 = 2
_EXPECTED_LEN_RESULTS_3 = 3
_EXPECTED_RESULT_MUTATIONS_APPLIED_5 = 5
_EXPECTED_SUMMARY_COMPLETED_2 = 2
_EXPECTED_SUMMARY_TOTAL_MUTATIONS_5 = 5
_EXPECTED_SUMMARY_TOTAL_PASSES_2 = 2
_EXPECTED_TOTAL_PASSES_2 = 2


class _Binary:
    path = Path("fixtures/dataset/elf_x86_64")


class FakePass(MutationPass):
    """Fake mutation pass for testing."""

    def __init__(self, name: str, result: dict | None = None, should_fail: bool = False):
        super().__init__(name=name, config={})
        self._result = result or {"mutations_applied": 1}
        self._should_fail = should_fail
        self.apply_called = False

    def apply(self, binary):
        self.apply_called = True
        if self._should_fail:
            raise RuntimeError(f"Pass {self.name} failed")
        return self._result


class TestPassDependency:
    """Test PassDependency dataclass."""

    def test_basic_dependency(self):
        """Create basic dependency."""
        dep = PassDependency("test", requires=["dep1"], conflicts=["conflict1"])
        expect(getattr(dep, MUTATION_NAME_KEY) == "test")
        expect(not ("dep1" not in dep.requires))
        expect(not ("conflict1" not in dep.conflicts))

    def test_optional_dependency(self):
        """Create optional dependency."""
        dep = PassDependency("test", optional=True)
        expect(not (dep.optional is not True))


class TestPassResult:
    """Test PassResult dataclass."""

    def test_completed_result(self):
        """Create completed result."""
        result = PassResult(
            **{MUTATION_NAME_KEY: "test"},
            status=PassStatus.COMPLETED,
            result={"key": "value"},
            duration_seconds=1.5,
            mutations_applied=5,
        )
        expect(getattr(result, MUTATION_NAME_KEY) == "test")
        expect(result.status == PassStatus.COMPLETED)
        expect(result.mutations_applied == _EXPECTED_RESULT_MUTATIONS_APPLIED_5)

    def test_failed_result(self):
        """Create failed result."""
        result = PassResult(
            **{MUTATION_NAME_KEY: "test"},
            status=PassStatus.FAILED,
            error="Something went wrong",
        )
        expect(result.status == PassStatus.FAILED)
        expect(not ("wrong" not in result.error))

    def test_to_dict(self):
        """Convert result to dictionary."""
        result = PassResult(
            **{MUTATION_NAME_KEY: "test"},
            status=PassStatus.COMPLETED,
            result={"key": "value"},
            mutations_applied=3,
        )
        d = result.to_dict()
        expect(d[MUTATION_NAME_KEY] == "test")
        expect(d["status"] == "completed")
        expect(d["mutations_applied"] == _EXPECTED_D_MUTATIONS_APPLIED_3)


class TestDependencyResolver:
    """Test DependencyResolver."""

    def test_no_dependencies(self):
        """Resolve passes with no dependencies."""
        resolver = DependencyResolver()
        passes = [
            FakePass("pass1"),
            FakePass("pass2"),
        ]
        plan = resolver.resolve(passes)

        expect(not (len(plan.stages) < 1))
        total_passes = sum(len(stage) for stage in plan.stages)
        expect(total_passes == _EXPECTED_TOTAL_PASSES_2)

    def test_sequential_dependencies(self):
        """Resolve passes with sequential dependencies."""
        custom_deps = {
            "pass2": PassDependency("pass2", requires=["pass1"]),
        }
        resolver = DependencyResolver(custom_deps)
        passes = [
            FakePass("pass1"),
            FakePass("pass2"),
        ]
        plan = resolver.resolve(passes)

        expect(not (len(plan.stages) < _EXPECTED_LEN_PLAN_STAGES_2))
        pass1_stage = plan.get_stage("pass1")
        pass2_stage = plan.get_stage("pass2")
        expect(not (pass1_stage >= pass2_stage))

    def test_conflict_detection(self):
        """Detect conflicting passes."""
        custom_deps = {
            "pass2": PassDependency("pass2", conflicts=["pass1"]),
        }
        resolver = DependencyResolver(custom_deps)
        passes = [
            FakePass("pass1"),
            FakePass("pass2"),
        ]

        conflicts = resolver.check_conflicts(passes)

        expect(len(conflicts) == 1)
        expect(("pass1", "pass2") in conflicts or ("pass2", "pass1") in conflicts)

    def test_independent_passes_same_stage(self):
        """Independent passes can run in same stage."""
        resolver = DependencyResolver()
        passes = [
            FakePass("nop"),
            FakePass("dead-code"),
        ]
        plan = resolver.resolve(passes)

        pass1_stage = plan.get_stage("nop")
        pass2_stage = plan.get_stage("dead-code")

        expect(pass1_stage == pass2_stage)


class TestParallelMutationEngine:
    """Test ParallelMutationEngine."""

    def test_single_pass_execution(self):
        """Execute a single pass."""
        engine = ParallelMutationEngine(_Binary(), max_workers=1, use_checkpoints=False)
        passes = [FakePass("test")]

        results = engine.execute(passes)

        expect(not ("test" not in results))
        expect(results["test"].status == PassStatus.COMPLETED)

    def test_multiple_independent_passes(self):
        """Execute multiple independent passes."""
        engine = ParallelMutationEngine(_Binary(), max_workers=2, use_checkpoints=False)
        passes = [
            FakePass("pass1", result={"mutations_applied": 1}),
            FakePass("pass2", result={"mutations_applied": 2}),
        ]

        results = engine.execute(passes)

        expect(results["pass1"].status == PassStatus.COMPLETED)
        expect(results["pass2"].status == PassStatus.COMPLETED)

    def test_failed_pass_with_stop_on_error(self):
        """Stop on pass failure when configured."""
        engine = ParallelMutationEngine(_Binary(), max_workers=1, use_checkpoints=False)
        passes = [
            FakePass("pass1", should_fail=True),
            FakePass("pass2"),
        ]

        results = engine.execute(passes, stop_on_error=True)

        expect(results["pass1"].status == PassStatus.FAILED)

    def test_continue_on_error(self):
        """Continue after pass failure when configured."""
        engine = ParallelMutationEngine(_Binary(), max_workers=1, use_checkpoints=False)
        passes = [
            FakePass("pass1", should_fail=True),
            FakePass("pass2"),
        ]

        custom_deps = {
            "pass2": PassDependency("pass2", requires=[]),
        }
        engine.resolver = DependencyResolver(custom_deps)

        results = engine.execute(passes, stop_on_error=False)

        expect(results["pass1"].status == PassStatus.FAILED)
        expect(results["pass2"].status == PassStatus.COMPLETED)

    def test_get_results_summary(self):
        """Get results summary."""
        engine = ParallelMutationEngine(_Binary(), max_workers=1, use_checkpoints=False)
        passes = [
            FakePass("pass1", result={"mutations_applied": 3}),
            FakePass("pass2", result={"mutations_applied": 2}),
        ]

        engine.execute(passes)
        summary = engine.get_results_summary()

        expect(summary["total_passes"] == _EXPECTED_SUMMARY_TOTAL_PASSES_2)
        expect(summary["completed"] == _EXPECTED_SUMMARY_COMPLETED_2)
        expect(summary["total_mutations"] == _EXPECTED_SUMMARY_TOTAL_MUTATIONS_5)


class TestExecuteParallel:
    """Test convenience function."""

    def test_execute_parallel_basic(self):
        """Test basic parallel execution."""
        passes = [
            FakePass("pass1"),
            FakePass("pass2"),
        ]

        results = execute_parallel(_Binary(), passes)

        expect(not ("pass1" not in results))
        expect(not ("pass2" not in results))

    def test_execute_parallel_with_workers(self):
        """Test parallel execution with worker count."""
        passes = [
            FakePass("pass1"),
            FakePass("pass2"),
            FakePass("pass3"),
        ]

        results = execute_parallel(_Binary(), passes, max_workers=2)

        expect(len(results) == _EXPECTED_LEN_RESULTS_3)


class TestPassStatus:
    """Test PassStatus enum."""

    def test_status_values(self):
        """Test all status values."""
        expect(PassStatus.PENDING.value == "pending")
        expect(PassStatus.RUNNING.value == "running")
        expect(PassStatus.COMPLETED.value == "completed")
        expect(PassStatus.FAILED.value == "failed")
        expect(PassStatus.SKIPPED.value == "skipped")
        expect(PassStatus.ROLLED_BACK.value == "rolled_back")


class TestExecutionPlan:
    """Test ExecutionPlan."""

    def test_get_stage(self):
        """Test getting stage for a pass."""
        plan = ExecutionPlan(
            passes=[],
            stages=[["pass1", "pass2"], ["pass3"]],
        )

        expect(plan.get_stage("pass1") == 0)
        expect(plan.get_stage("pass2") == 0)
        expect(plan.get_stage("pass3") == 1)
        expect(plan.get_stage("unknown") == -1)


class TestBinaryFileLock:
    """Test BinaryFileLock for concurrent write protection."""

    def test_basic_lock_acquire_release(self, tmp_path: Path):
        """Test basic lock acquisition and release."""
        binary_file_lock = importlib.import_module("r2morph.core.parallel").BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock = binary_file_lock(binary_path)

        expect(not (lock.is_locked()))
        expect(lock.acquire())
        expect(lock.is_locked())
        lock.release()
        expect(not (lock.is_locked()))

    def test_lock_context_manager(self, tmp_path: Path):
        """Test lock as context manager."""
        binary_file_lock = importlib.import_module("r2morph.core.parallel").BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock = binary_file_lock(binary_path)

        expect(not (lock.is_locked()))
        with lock:
            expect(lock.is_locked())
        expect(not (lock.is_locked()))

    def test_non_blocking_acquire(self, tmp_path: Path):
        """Test non-blocking lock acquisition."""
        binary_file_lock = importlib.import_module("r2morph.core.parallel").BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock1 = binary_file_lock(binary_path)
        lock2 = binary_file_lock(binary_path)

        expect(lock1.acquire())
        expect(lock1.is_locked())

        # Non-blocking should return False if already locked
        expect(not (lock2.acquire(blocking=False)))
        expect(not (lock2.is_locked()))

        lock1.release()
        expect(not (lock1.is_locked()))

    def test_reentrant_lock(self, tmp_path: Path):
        """Test that acquiring already-held lock returns True."""
        binary_file_lock = importlib.import_module("r2morph.core.parallel").BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock = binary_file_lock(binary_path)

        expect(lock.acquire())
        expect(lock.is_locked())

        # Re-acquiring should return True since we already hold it
        expect(lock.acquire())

        lock.release()
        expect(not (lock.is_locked()))

    def test_lock_cleanup(self, tmp_path: Path):
        """Test that lock file is properly cleaned up."""
        binary_file_lock = importlib.import_module("r2morph.core.parallel").BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock = binary_file_lock(binary_path)

        with lock:
            pass

        expect(not (lock.is_locked()))
        # Lock file should still exist (that's normal for file locks)
        lock_path = binary_path.with_suffix(binary_path.suffix + ".lock")
        expect(lock_path.exists())
