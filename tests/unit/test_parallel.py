"""
Tests for parallel mutation execution.
"""

from unittest.mock import MagicMock
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
        assert dep.pass_name == "test"
        assert "dep1" in dep.requires
        assert "conflict1" in dep.conflicts

    def test_optional_dependency(self):
        """Create optional dependency."""
        dep = PassDependency("test", optional=True)
        assert dep.optional is True


class TestPassResult:
    """Test PassResult dataclass."""

    def test_completed_result(self):
        """Create completed result."""
        result = PassResult(
            pass_name="test",
            status=PassStatus.COMPLETED,
            result={"key": "value"},
            duration_seconds=1.5,
            mutations_applied=5,
        )
        assert result.pass_name == "test"
        assert result.status == PassStatus.COMPLETED
        assert result.mutations_applied == 5

    def test_failed_result(self):
        """Create failed result."""
        result = PassResult(
            pass_name="test",
            status=PassStatus.FAILED,
            error="Something went wrong",
        )
        assert result.status == PassStatus.FAILED
        assert "wrong" in result.error

    def test_to_dict(self):
        """Convert result to dictionary."""
        result = PassResult(
            pass_name="test",
            status=PassStatus.COMPLETED,
            result={"key": "value"},
            mutations_applied=3,
        )
        d = result.to_dict()
        assert d["pass_name"] == "test"
        assert d["status"] == "completed"
        assert d["mutations_applied"] == 3


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

        assert len(plan.stages) >= 1
        total_passes = sum(len(stage) for stage in plan.stages)
        assert total_passes == 2

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

        assert len(plan.stages) >= 2
        pass1_stage = plan.get_stage("pass1")
        pass2_stage = plan.get_stage("pass2")
        assert pass1_stage < pass2_stage

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

        assert len(conflicts) == 1
        assert ("pass1", "pass2") in conflicts or ("pass2", "pass1") in conflicts

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

        assert pass1_stage == pass2_stage


class TestParallelMutationEngine:
    """Test ParallelMutationEngine."""

    def test_single_pass_execution(self):
        """Execute a single pass."""
        mock_binary = MagicMock()
        mock_binary.path = Path("/tmp/test")

        engine = ParallelMutationEngine(mock_binary, max_workers=1, use_checkpoints=False)
        passes = [FakePass("test")]

        results = engine.execute(passes)

        assert "test" in results
        assert results["test"].status == PassStatus.COMPLETED

    def test_multiple_independent_passes(self):
        """Execute multiple independent passes."""
        mock_binary = MagicMock()
        mock_binary.path = Path("/tmp/test")

        engine = ParallelMutationEngine(mock_binary, max_workers=2, use_checkpoints=False)
        passes = [
            FakePass("pass1", result={"mutations_applied": 1}),
            FakePass("pass2", result={"mutations_applied": 2}),
        ]

        results = engine.execute(passes)

        assert results["pass1"].status == PassStatus.COMPLETED
        assert results["pass2"].status == PassStatus.COMPLETED

    def test_failed_pass_with_stop_on_error(self):
        """Stop on pass failure when configured."""
        mock_binary = MagicMock()
        mock_binary.path = Path("/tmp/test")

        engine = ParallelMutationEngine(mock_binary, max_workers=1, use_checkpoints=False)
        passes = [
            FakePass("pass1", should_fail=True),
            FakePass("pass2"),
        ]

        results = engine.execute(passes, stop_on_error=True)

        assert results["pass1"].status == PassStatus.FAILED

    def test_continue_on_error(self):
        """Continue after pass failure when configured."""
        mock_binary = MagicMock()
        mock_binary.path = Path("/tmp/test")

        engine = ParallelMutationEngine(mock_binary, max_workers=1, use_checkpoints=False)
        passes = [
            FakePass("pass1", should_fail=True),
            FakePass("pass2"),
        ]

        custom_deps = {
            "pass2": PassDependency("pass2", requires=[]),
        }
        engine.resolver = DependencyResolver(custom_deps)

        results = engine.execute(passes, stop_on_error=False)

        assert results["pass1"].status == PassStatus.FAILED
        assert results["pass2"].status == PassStatus.COMPLETED

    def test_get_results_summary(self):
        """Get results summary."""
        mock_binary = MagicMock()
        mock_binary.path = Path("/tmp/test")

        engine = ParallelMutationEngine(mock_binary, max_workers=1, use_checkpoints=False)
        passes = [
            FakePass("pass1", result={"mutations_applied": 3}),
            FakePass("pass2", result={"mutations_applied": 2}),
        ]

        engine.execute(passes)
        summary = engine.get_results_summary()

        assert summary["total_passes"] == 2
        assert summary["completed"] == 2
        assert summary["total_mutations"] == 5


class TestExecuteParallel:
    """Test convenience function."""

    def test_execute_parallel_basic(self):
        """Test basic parallel execution."""
        mock_binary = MagicMock()
        mock_binary.path = Path("/tmp/test")

        passes = [
            FakePass("pass1"),
            FakePass("pass2"),
        ]

        results = execute_parallel(mock_binary, passes)

        assert "pass1" in results
        assert "pass2" in results

    def test_execute_parallel_with_workers(self):
        """Test parallel execution with worker count."""
        mock_binary = MagicMock()
        mock_binary.path = Path("/tmp/test")

        passes = [
            FakePass("pass1"),
            FakePass("pass2"),
            FakePass("pass3"),
        ]

        results = execute_parallel(mock_binary, passes, max_workers=2)

        assert len(results) == 3


class TestPassStatus:
    """Test PassStatus enum."""

    def test_status_values(self):
        """Test all status values."""
        assert PassStatus.PENDING.value == "pending"
        assert PassStatus.RUNNING.value == "running"
        assert PassStatus.COMPLETED.value == "completed"
        assert PassStatus.FAILED.value == "failed"
        assert PassStatus.SKIPPED.value == "skipped"
        assert PassStatus.ROLLED_BACK.value == "rolled_back"


class TestExecutionPlan:
    """Test ExecutionPlan."""

    def test_get_stage(self):
        """Test getting stage for a pass."""
        plan = ExecutionPlan(
            passes=[],
            stages=[["pass1", "pass2"], ["pass3"]],
        )

        assert plan.get_stage("pass1") == 0
        assert plan.get_stage("pass2") == 0
        assert plan.get_stage("pass3") == 1
        assert plan.get_stage("unknown") == -1


class TestBinaryFileLock:
    """Test BinaryFileLock for concurrent write protection."""

    def test_basic_lock_acquire_release(self, tmp_path: Path):
        """Test basic lock acquisition and release."""
        from r2morph.core.parallel import BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock = BinaryFileLock(binary_path)

        assert not lock.is_locked()
        assert lock.acquire()
        assert lock.is_locked()
        lock.release()
        assert not lock.is_locked()

    def test_lock_context_manager(self, tmp_path: Path):
        """Test lock as context manager."""
        from r2morph.core.parallel import BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock = BinaryFileLock(binary_path)

        assert not lock.is_locked()
        with lock:
            assert lock.is_locked()
        assert not lock.is_locked()

    def test_non_blocking_acquire(self, tmp_path: Path):
        """Test non-blocking lock acquisition."""
        from r2morph.core.parallel import BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock1 = BinaryFileLock(binary_path)
        lock2 = BinaryFileLock(binary_path)

        assert lock1.acquire()
        assert lock1.is_locked()

        # Non-blocking should return False if already locked
        assert not lock2.acquire(blocking=False)
        assert not lock2.is_locked()

        lock1.release()
        assert not lock1.is_locked()

    def test_reentrant_lock(self, tmp_path: Path):
        """Test that acquiring already-held lock returns True."""
        from r2morph.core.parallel import BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock = BinaryFileLock(binary_path)

        assert lock.acquire()
        assert lock.is_locked()

        # Re-acquiring should return True since we already hold it
        assert lock.acquire()

        lock.release()
        assert not lock.is_locked()

    def test_lock_cleanup(self, tmp_path: Path):
        """Test that lock file is properly cleaned up."""
        from r2morph.core.parallel import BinaryFileLock

        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x00" * 100)

        lock = BinaryFileLock(binary_path)

        with lock:
            pass

        assert not lock.is_locked()
        # Lock file should still exist (that's normal for file locks)
        lock_path = binary_path.with_suffix(binary_path.suffix + ".lock")
        assert lock_path.exists()
