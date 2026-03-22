"""
Tests for parallel executor module.
"""

import pytest
from unittest.mock import Mock

from r2morph.core.parallel_executor import (
    TaskStatus,
    ResolutionStrategy,
    MutationTask,
    MutationResult,
    WorkQueue,
    ResultMerger,
    ParallelMutator,
    create_parallel_mutator,
)


class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_status_values(self):
        """Test status enum values."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.READY.value == "ready"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.SKIPPED.value == "skipped"


class TestResolutionStrategy:
    """Tests for ResolutionStrategy enum."""

    def test_strategy_values(self):
        """Test strategy enum values."""
        assert ResolutionStrategy.SKIP.value == "skip"
        assert ResolutionStrategy.REORDER.value == "reorder"
        assert ResolutionStrategy.MERGE.value == "merge"
        assert ResolutionStrategy.ABORT.value == "abort"


class TestMutationTask:
    """Tests for MutationTask class."""

    def test_task_creation(self):
        """Test task creation."""
        task = MutationTask(
            task_id=1,
            function_address=0x1000,
            function_name="test_func",
        )

        assert task.task_id == 1
        assert task.function_address == 0x1000
        assert task.function_name == "test_func"
        assert task.status == TaskStatus.PENDING
        assert len(task.passes) == 0

    def test_task_with_dependencies(self):
        """Test task with dependencies."""
        task = MutationTask(
            task_id=2,
            function_address=0x2000,
            dependencies=[1, 3],
            priority=5,
        )

        assert task.dependencies == [1, 3]
        assert task.priority == 5

    def test_task_is_ready(self):
        """Test is_ready method."""
        task = MutationTask(
            task_id=1,
            function_address=0x1000,
            dependencies=[2, 3],
        )

        assert not task.is_ready(set())
        assert not task.is_ready({2})
        assert not task.is_ready({2, 4})
        assert task.is_ready({2, 3})
        assert task.is_ready({1, 2, 3, 4})

    def test_task_hash(self):
        """Test task hashing."""
        task1 = MutationTask(task_id=1, function_address=0x1000)
        task2 = MutationTask(task_id=1, function_address=0x1000)

        assert hash(task1) == hash(task2)
        # Note: hash is based on task_id only, which allows lookup in dicts/sets


class TestMutationResult:
    """Tests for MutationResult class."""

    def test_result_creation(self):
        """Test result creation."""
        result = MutationResult(
            task_id=1,
            function_address=0x1000,
            function_name="test",
            success=True,
        )

        assert result.task_id == 1
        assert result.success is True
        assert len(result.mutations_applied) == 0

    def test_result_to_dict(self):
        """Test result dictionary conversion."""
        result = MutationResult(
            task_id=1,
            function_address=0x1000,
            function_name="test",
            success=True,
            mutations_applied=[{"type": "nop"}],
            bytes_modified=10,
            execution_time=0.5,
        )

        d = result.to_dict()

        assert d["task_id"] == 1
        assert d["function_address"] == "0x1000"
        assert d["success"] is True
        assert len(d["mutations_applied"]) == 1
        assert d["bytes_modified"] == 10
        assert d["execution_time"] == 0.5


class TestWorkQueue:
    """Tests for WorkQueue class."""

    def test_queue_creation(self):
        """Test queue creation."""
        queue = WorkQueue()

        assert queue.get_pending_count() == 0
        assert queue.get_running_count() == 0
        assert queue.get_completed_count() == 0

    def test_add_task(self):
        """Test adding tasks."""
        queue = WorkQueue()

        task_id = queue.add_task(
            function_address=0x1000,
            function_name="func1",
        )

        assert task_id == 0
        assert queue.get_pending_count() == 1

    def test_add_multiple_tasks(self):
        """Test adding multiple tasks."""
        queue = WorkQueue()

        id1 = queue.add_task(function_address=0x1000)
        id2 = queue.add_task(function_address=0x2000)
        id3 = queue.add_task(function_address=0x3000)

        assert id1 == 0
        assert id2 == 1
        assert id3 == 2
        assert queue.get_pending_count() == 3

    def test_get_ready_tasks(self):
        """Test getting ready tasks."""
        queue = WorkQueue()

        queue.add_task(function_address=0x1000, priority=1)
        queue.add_task(function_address=0x2000, priority=3)
        queue.add_task(function_address=0x3000, priority=2)

        ready = queue.get_ready_tasks()

        assert len(ready) == 3
        assert ready[0].priority == 3
        assert ready[1].priority == 2
        assert ready[2].priority == 1

    def test_get_ready_tasks_with_dependencies(self):
        """Test getting ready tasks with dependencies."""
        queue = WorkQueue()

        id1 = queue.add_task(function_address=0x1000)
        id2 = queue.add_task(function_address=0x2000, dependencies=[id1])
        queue.add_task(function_address=0x3000, dependencies=[id1, id2])

        ready = queue.get_ready_tasks()
        assert len(ready) == 1
        assert ready[0].task_id == id1

        queue.mark_completed(
            id1, MutationResult(task_id=id1, function_address=0x1000, function_name="f1", success=True)
        )

        ready = queue.get_ready_tasks()
        assert len(ready) == 1
        assert ready[0].task_id == id2

    def test_mark_running(self):
        """Test marking task as running."""
        queue = WorkQueue()

        task_id = queue.add_task(function_address=0x1000)
        queue.mark_running(task_id)

        assert queue.get_running_count() == 1
        assert queue.get_pending_count() == 0

    def test_mark_completed(self):
        """Test marking task as completed."""
        queue = WorkQueue()

        task_id = queue.add_task(function_address=0x1000)
        result = MutationResult(task_id=task_id, function_address=0x1000, function_name="test", success=True)

        queue.mark_running(task_id)
        queue.mark_completed(task_id, result)

        assert queue.get_completed_count() == 1
        assert queue.get_running_count() == 0

    def test_mark_failed(self):
        """Test marking task as failed."""
        queue = WorkQueue()

        task_id = queue.add_task(function_address=0x1000)

        queue.mark_running(task_id)
        queue.mark_failed(task_id, "Test error")

        assert queue.get_failed_count() == 1
        assert queue.get_running_count() == 0

    def test_is_empty(self):
        """Test is_empty method."""
        queue = WorkQueue()

        assert queue.is_empty()

        queue.add_task(function_address=0x1000)
        assert not queue.is_empty()

    def test_clear(self):
        """Test clearing queue."""
        queue = WorkQueue()

        queue.add_task(function_address=0x1000)
        queue.add_task(function_address=0x2000)

        queue.clear()

        assert queue.get_pending_count() == 0
        assert queue.get_completed_count() == 0


class TestResultMerger:
    """Tests for ResultMerger class."""

    def test_merger_creation(self):
        """Test merger creation."""
        merger = ResultMerger()

        assert len(merger._results) == 0
        assert len(merger._conflicts) == 0

    def test_add_result(self):
        """Test adding results."""
        merger = ResultMerger()
        result = MutationResult(
            task_id=1,
            function_address=0x1000,
            function_name="test",
            success=True,
        )

        merger.add_result(result)

        assert len(merger._results) == 1

    def test_merge_results(self):
        """Test merging results."""
        merger = ResultMerger()
        mock_binary = Mock()

        results = [
            MutationResult(1, 0x1000, "f1", True, mutations_applied=[{"a": 1}], bytes_modified=10, execution_time=0.1),
            MutationResult(2, 0x2000, "f2", True, mutations_applied=[{"b": 2}], bytes_modified=20, execution_time=0.2),
            MutationResult(3, 0x3000, "f3", False, error="failed"),
        ]

        merged = merger.merge(mock_binary, results)

        assert merged["total_functions"] == 3
        assert merged["successful"] == 2
        assert merged["failed"] == 1
        assert merged["total_mutations"] == 2
        assert merged["total_bytes_modified"] == 30
        assert merged["total_time"] == pytest.approx(0.3)

    def test_detect_conflicts(self):
        """Test conflict detection."""
        merger = ResultMerger()

        results = [
            MutationResult(1, 0x1000, "f1", True, mutations_applied=[{"address": 0x1000, "size": 10}]),
            MutationResult(2, 0x1000, "f2", True, mutations_applied=[{"address": 0x1005, "size": 10}]),
        ]

        conflicts = merger.detect_conflicts(results)

        assert len(conflicts) == 1
        assert conflicts[0]["function"] == "0x1000"

    def test_no_conflicts(self):
        """Test no conflicts when regions don't overlap."""
        merger = ResultMerger()

        results = [
            MutationResult(1, 0x1000, "f1", True, mutations_applied=[{"address": 0x1000, "size": 10}]),
            MutationResult(2, 0x2000, "f2", True, mutations_applied=[{"address": 0x2000, "size": 10}]),
        ]

        conflicts = merger.detect_conflicts(results)

        assert len(conflicts) == 0

    def test_resolve_conflicts_skip(self):
        """Test conflict resolution with skip strategy."""
        merger = ResultMerger()

        # Create conflicts as dictionaries (as detect_conflicts produces)
        conflicts = [
            {
                "function": "0x1000",
                "region1": (0x1000, 0x1010),
                "region2": (0x1005, 0x1015),
                "task_ids": [1, 2],
            }
        ]

        resolutions = merger.resolve_conflicts(conflicts, ResolutionStrategy.SKIP)

        assert len(resolutions) == 1
        assert resolutions[0]["strategy"] == "skip"
        assert "0x1000" in resolutions[0]["description"]

    def test_resolve_conflicts_reorder(self):
        """Test conflict resolution with reorder strategy."""
        merger = ResultMerger()

        conflicts = [
            {
                "function": "0x1000",
                "region1": (0x1000, 0x1010),
                "region2": (0x1005, 0x1015),
                "task_ids": [1, 2],
            }
        ]

        resolutions = merger.resolve_conflicts(conflicts, ResolutionStrategy.REORDER)

        assert len(resolutions) == 1
        assert resolutions[0]["strategy"] == "reorder"

    def test_clear(self):
        """Test clearing merger."""
        merger = ResultMerger()

        merger.add_result(MutationResult(1, 0x1000, "test", True))
        merger.clear()

        assert len(merger._results) == 0


class TestParallelMutator:
    """Tests for ParallelMutator class."""

    def test_mutator_creation(self):
        """Test mutator creation."""
        mutator = create_parallel_mutator(max_workers=4)

        assert mutator.max_workers == 4
        assert mutator.use_threads is False

    def test_mutator_creation_with_threads(self):
        """Test mutator creation with threads."""
        mutator = create_parallel_mutator(max_workers=2, use_threads=True)

        assert mutator.max_workers == 2
        assert mutator.use_threads is True

    def test_create_tasks_from_call_graph(self):
        """Test creating tasks from call graph."""
        mutator = ParallelMutator()

        functions = [
            {"offset": 0x1000, "name": "func1"},
            {"offset": 0x2000, "name": "func2"},
            {"offset": 0x3000, "name": "func3"},
        ]

        call_graph = {
            0x1000: [0x2000],
            0x2000: [0x3000],
        }

        task_ids = mutator.create_tasks_from_call_graph(functions, call_graph)

        assert len(task_ids) == 3

    def test_create_tasks_without_call_graph(self):
        """Test creating tasks without call graph."""
        mutator = ParallelMutator()

        functions = [
            {"offset": 0x1000, "name": "func1"},
            {"offset": 0x2000, "name": "func2"},
        ]

        task_ids = mutator.create_tasks_from_call_graph(functions)

        assert len(task_ids) == 2

    def test_get_statistics(self):
        """Test getting statistics."""
        mutator = ParallelMutator()

        stats = mutator.get_statistics()

        assert "pending_tasks" in stats
        assert "running_tasks" in stats
        assert "completed_tasks" in stats
        assert "failed_tasks" in stats
        assert "workers" in stats

    def test_clear(self):
        """Test clearing mutator."""
        mutator = ParallelMutator()

        mutator.create_tasks_from_call_graph([{"offset": 0x1000}])
        mutator.clear()

        assert mutator._work_queue.get_pending_count() == 0

    def test_progress_callback(self):
        """Test progress callback."""
        mutator = ParallelMutator()

        calls = []

        def callback(completed, total, task):
            calls.append((completed, total, task.task_id))

        mutator.set_progress_callback(callback)

        assert mutator._progress_callback is not None


class TestWorkQueueAdvanced:
    """Advanced tests for WorkQueue."""

    def test_priority_ordering(self):
        """Test that tasks are ordered by priority."""
        queue = WorkQueue()

        queue.add_task(function_address=0x1000, priority=1)
        queue.add_task(function_address=0x2000, priority=5)
        queue.add_task(function_address=0x3000, priority=3)

        ready = queue.get_ready_tasks()

        assert ready[0].priority == 5
        assert ready[1].priority == 3
        assert ready[2].priority == 1

    def test_max_tasks_limit(self):
        """Test max tasks limit in get_ready_tasks."""
        queue = WorkQueue()

        for i in range(10):
            queue.add_task(function_address=0x1000 + i * 0x100)

        ready = queue.get_ready_tasks(max_tasks=5)

        assert len(ready) == 5

    def test_get_dependencies(self):
        """Test getting dependencies."""
        queue = WorkQueue()

        id1 = queue.add_task(function_address=0x1000)
        id2 = queue.add_task(function_address=0x2000, dependencies=[id1, 0])

        deps = queue.get_dependencies(id2)

        assert id1 in deps
        assert 0 in deps


class TestResultMergerAdvanced:
    """Advanced tests for ResultMerger."""

    def test_merge_empty_results(self):
        """Test merging empty results."""
        merger = ResultMerger()
        mock_binary = Mock()

        merged = merger.merge(mock_binary, [])

        assert merged["total_functions"] == 0
        assert merged["successful"] == 0
        assert merged["failed"] == 0

    def test_conflict_detection_different_functions(self):
        """Test that conflicts are detected per function."""
        merger = ResultMerger()

        results = [
            MutationResult(1, 0x1000, "f1", True, mutations_applied=[{"address": 0x1000, "size": 20}]),
            MutationResult(2, 0x2000, "f2", True, mutations_applied=[{"address": 0x1005, "size": 10}]),
        ]

        conflicts = merger.detect_conflicts(results)

        assert len(conflicts) == 0
