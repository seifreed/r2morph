"""
Tests for parallel executor module.
"""

import pytest

from r2morph.core.parallel_executor import (
    ParallelMutator,
    create_parallel_mutator,
)
from r2morph.core.parallel_executor_models import MutationResult, MutationTask, ResolutionStrategy, TaskStatus
from r2morph.core.parallel_result_merger import ResultMerger
from r2morph.core.parallel_work_queue import WorkQueue
from tests.utils.assertions import expect

_EXPECTED_D_BYTES_MODIFIED_10 = 10
_EXPECTED_D_EXECUTION_TIME_0_5 = 0.5
_EXPECTED_ID3_2 = 2
_EXPECTED_LEN_READY_3 = 3
_EXPECTED_LEN_READY_5 = 5
_EXPECTED_LEN_TASK_IDS_2 = 2
_EXPECTED_LEN_TASK_IDS_3 = 3
_EXPECTED_MERGED_SUCCESSFUL_2 = 2
_EXPECTED_MERGED_TOTAL_BYTES_MODIFIED_30 = 30
_EXPECTED_MERGED_TOTAL_FUNCTIONS_3 = 3
_EXPECTED_MERGED_TOTAL_MUTATIONS_2 = 2
_EXPECTED_MUTATOR_MAX_WORKERS_2 = 2
_EXPECTED_MUTATOR_MAX_WORKERS_4 = 4
_EXPECTED_QUEUE_GET_PENDING_COUNT_3 = 3
_EXPECTED_READY_0_PRIORITY_3 = 3
_EXPECTED_READY_0_PRIORITY_5 = 5
_EXPECTED_READY_1_PRIORITY_2 = 2
_EXPECTED_READY_1_PRIORITY_3 = 3
_EXPECTED_TASK_FUNCTION_ADDRESS_4096 = 0x1000
_EXPECTED_TASK_PRIORITY_5 = 5


class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_status_values(self):
        """Test status enum values."""
        expect(TaskStatus.PENDING.value == "pending")
        expect(TaskStatus.READY.value == "ready")
        expect(TaskStatus.RUNNING.value == "running")
        expect(TaskStatus.COMPLETED.value == "completed")
        expect(TaskStatus.FAILED.value == "failed")
        expect(TaskStatus.SKIPPED.value == "skipped")


class TestResolutionStrategy:
    """Tests for ResolutionStrategy enum."""

    def test_strategy_values(self):
        """Test strategy enum values."""
        expect(ResolutionStrategy.SKIP.value == "skip")
        expect(ResolutionStrategy.REORDER.value == "reorder")
        expect(ResolutionStrategy.MERGE.value == "merge")
        expect(ResolutionStrategy.ABORT.value == "abort")


class TestMutationTask:
    """Tests for MutationTask class."""

    def test_task_creation(self):
        """Test task creation."""
        task = MutationTask(
            task_id=1,
            function_address=0x1000,
            function_name="test_func",
        )

        expect(task.task_id == 1)
        expect(task.function_address == _EXPECTED_TASK_FUNCTION_ADDRESS_4096)
        expect(task.function_name == "test_func")
        expect(task.status == TaskStatus.PENDING)
        expect(len(task.passes) == 0)

    def test_task_with_dependencies(self):
        """Test task with dependencies."""
        task = MutationTask(
            task_id=2,
            function_address=0x2000,
            dependencies=[1, 3],
            priority=5,
        )

        expect(task.dependencies == [1, 3])
        expect(task.priority == _EXPECTED_TASK_PRIORITY_5)

    def test_task_is_ready(self):
        """Test is_ready method."""
        task = MutationTask(
            task_id=1,
            function_address=0x1000,
            dependencies=[2, 3],
        )

        expect(not (task.is_ready(set())))
        expect(not (task.is_ready({2})))
        expect(not (task.is_ready({2, 4})))
        expect(task.is_ready({2, 3}))
        expect(task.is_ready({1, 2, 3, 4}))

    def test_task_hash(self):
        """Test task hashing."""
        task1 = MutationTask(task_id=1, function_address=0x1000)
        task2 = MutationTask(task_id=1, function_address=0x1000)

        expect(hash(task1) == hash(task2))
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

        expect(result.task_id == 1)
        expect(not (result.success is not True))
        expect(len(result.mutations_applied) == 0)

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

        expect(d["task_id"] == 1)
        expect(d["function_address"] == "0x1000")
        expect(not (d["success"] is not True))
        expect(len(d["mutations_applied"]) == 1)
        expect(d["bytes_modified"] == _EXPECTED_D_BYTES_MODIFIED_10)
        expect(d["execution_time"] == _EXPECTED_D_EXECUTION_TIME_0_5)


class TestWorkQueue:
    """Tests for WorkQueue class."""

    def test_queue_creation(self):
        """Test queue creation."""
        queue = WorkQueue()

        expect(queue.get_pending_count() == 0)
        expect(queue.get_running_count() == 0)
        expect(queue.get_completed_count() == 0)

    def test_add_task(self):
        """Test adding tasks."""
        queue = WorkQueue()

        task_id = queue.add_task(
            function_address=0x1000,
            function_name="func1",
        )

        expect(task_id == 0)
        expect(queue.get_pending_count() == 1)

    def test_add_multiple_tasks(self):
        """Test adding multiple tasks."""
        queue = WorkQueue()

        id1 = queue.add_task(function_address=0x1000)
        id2 = queue.add_task(function_address=0x2000)
        id3 = queue.add_task(function_address=0x3000)

        expect(id1 == 0)
        expect(id2 == 1)
        expect(id3 == _EXPECTED_ID3_2)
        expect(queue.get_pending_count() == _EXPECTED_QUEUE_GET_PENDING_COUNT_3)

    def test_get_ready_tasks(self):
        """Test getting ready tasks."""
        queue = WorkQueue()

        queue.add_task(function_address=0x1000, priority=1)
        queue.add_task(function_address=0x2000, priority=3)
        queue.add_task(function_address=0x3000, priority=2)

        ready = queue.get_ready_tasks()

        expect(len(ready) == _EXPECTED_LEN_READY_3)
        expect(ready[0].priority == _EXPECTED_READY_0_PRIORITY_3)
        expect(ready[1].priority == _EXPECTED_READY_1_PRIORITY_2)
        expect(ready[2].priority == 1)

    def test_get_ready_tasks_with_dependencies(self):
        """Test getting ready tasks with dependencies."""
        queue = WorkQueue()

        id1 = queue.add_task(function_address=0x1000)
        id2 = queue.add_task(function_address=0x2000, dependencies=[id1])
        queue.add_task(function_address=0x3000, dependencies=[id1, id2])

        ready = queue.get_ready_tasks()
        expect(len(ready) == 1)
        expect(ready[0].task_id == id1)

        queue.mark_completed(
            id1, MutationResult(task_id=id1, function_address=0x1000, function_name="f1", success=True)
        )

        ready = queue.get_ready_tasks()
        expect(len(ready) == 1)
        expect(ready[0].task_id == id2)

    def test_mark_running(self):
        """Test marking task as running."""
        queue = WorkQueue()

        task_id = queue.add_task(function_address=0x1000)
        queue.mark_running(task_id)

        expect(queue.get_running_count() == 1)
        expect(queue.get_pending_count() == 0)

    def test_mark_completed(self):
        """Test marking task as completed."""
        queue = WorkQueue()

        task_id = queue.add_task(function_address=0x1000)
        result = MutationResult(task_id=task_id, function_address=0x1000, function_name="test", success=True)

        queue.mark_running(task_id)
        queue.mark_completed(task_id, result)

        expect(queue.get_completed_count() == 1)
        expect(queue.get_running_count() == 0)

    def test_mark_failed(self):
        """Test marking task as failed."""
        queue = WorkQueue()

        task_id = queue.add_task(function_address=0x1000)

        queue.mark_running(task_id)
        queue.mark_failed(task_id, "Test error")

        expect(queue.get_failed_count() == 1)
        expect(queue.get_running_count() == 0)

    def test_is_empty(self):
        """Test is_empty method."""
        queue = WorkQueue()

        expect(queue.is_empty())

        queue.add_task(function_address=0x1000)
        expect(not (queue.is_empty()))

    def test_clear(self):
        """Test clearing queue."""
        queue = WorkQueue()

        queue.add_task(function_address=0x1000)
        queue.add_task(function_address=0x2000)

        queue.clear()

        expect(queue.get_pending_count() == 0)
        expect(queue.get_completed_count() == 0)


class TestResultMerger:
    """Tests for ResultMerger class."""

    def test_merger_creation(self):
        """Test merger creation."""
        merger = ResultMerger()

        expect(len(merger._results) == 0)
        expect(len(merger._conflicts) == 0)

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

        expect(len(merger._results) == 1)

    def test_merge_results(self):
        """Test merging results."""
        merger = ResultMerger()
        results = [
            MutationResult(1, 0x1000, "f1", True, mutations_applied=[{"a": 1}], bytes_modified=10, execution_time=0.1),
            MutationResult(2, 0x2000, "f2", True, mutations_applied=[{"b": 2}], bytes_modified=20, execution_time=0.2),
            MutationResult(3, 0x3000, "f3", False, error="failed"),
        ]

        merged = merger.merge(None, results)

        expect(merged["total_functions"] == _EXPECTED_MERGED_TOTAL_FUNCTIONS_3)
        expect(merged["successful"] == _EXPECTED_MERGED_SUCCESSFUL_2)
        expect(merged["failed"] == 1)
        expect(merged["total_mutations"] == _EXPECTED_MERGED_TOTAL_MUTATIONS_2)
        expect(merged["total_bytes_modified"] == _EXPECTED_MERGED_TOTAL_BYTES_MODIFIED_30)
        expect(merged["total_time"] == pytest.approx(0.3))

    def test_detect_conflicts(self):
        """Test conflict detection."""
        merger = ResultMerger()

        results = [
            MutationResult(1, 0x1000, "f1", True, mutations_applied=[{"address": 0x1000, "size": 10}]),
            MutationResult(2, 0x1000, "f2", True, mutations_applied=[{"address": 0x1005, "size": 10}]),
        ]

        conflicts = merger.detect_conflicts(results)

        expect(len(conflicts) == 1)
        expect(conflicts[0]["function"] == "0x1000")

    def test_no_conflicts(self):
        """Test no conflicts when regions don't overlap."""
        merger = ResultMerger()

        results = [
            MutationResult(1, 0x1000, "f1", True, mutations_applied=[{"address": 0x1000, "size": 10}]),
            MutationResult(2, 0x2000, "f2", True, mutations_applied=[{"address": 0x2000, "size": 10}]),
        ]

        conflicts = merger.detect_conflicts(results)

        expect(len(conflicts) == 0)

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

        expect(len(resolutions) == 1)
        expect(resolutions[0]["strategy"] == "skip")
        expect(not ("0x1000" not in resolutions[0]["description"]))

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

        expect(len(resolutions) == 1)
        expect(resolutions[0]["strategy"] == "reorder")

    def test_clear(self):
        """Test clearing merger."""
        merger = ResultMerger()

        merger.add_result(MutationResult(1, 0x1000, "test", True))
        merger.clear()

        expect(len(merger._results) == 0)


class TestParallelMutator:
    """Tests for ParallelMutator class."""

    def test_mutator_creation(self):
        """Test mutator creation."""
        mutator = create_parallel_mutator(max_workers=4)

        expect(mutator.max_workers == _EXPECTED_MUTATOR_MAX_WORKERS_4)
        expect(not (mutator.use_threads is not False))

    def test_mutator_creation_with_threads(self):
        """Test mutator creation with threads."""
        mutator = create_parallel_mutator(max_workers=2, use_threads=True)

        expect(mutator.max_workers == _EXPECTED_MUTATOR_MAX_WORKERS_2)
        expect(not (mutator.use_threads is not True))

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

        expect(len(task_ids) == _EXPECTED_LEN_TASK_IDS_3)

    def test_create_tasks_without_call_graph(self):
        """Test creating tasks without call graph."""
        mutator = ParallelMutator()

        functions = [
            {"offset": 0x1000, "name": "func1"},
            {"offset": 0x2000, "name": "func2"},
        ]

        task_ids = mutator.create_tasks_from_call_graph(functions)

        expect(len(task_ids) == _EXPECTED_LEN_TASK_IDS_2)

    def test_get_statistics(self):
        """Test getting statistics."""
        mutator = ParallelMutator()

        stats = mutator.get_statistics()

        expect(not ("pending_tasks" not in stats))
        expect(not ("running_tasks" not in stats))
        expect(not ("completed_tasks" not in stats))
        expect(not ("failed_tasks" not in stats))
        expect(not ("workers" not in stats))

    def test_clear(self):
        """Test clearing mutator."""
        mutator = ParallelMutator()

        mutator.create_tasks_from_call_graph([{"offset": 0x1000}])
        mutator.clear()

        expect(mutator._work_queue.get_pending_count() == 0)

    def test_progress_callback(self):
        """Test progress callback."""
        mutator = ParallelMutator()

        calls = []

        def callback(completed, total, task):
            calls.append((completed, total, task.task_id))

        mutator.set_progress_callback(callback)

        expect(mutator._progress_callback is not None)


class TestWorkQueueAdvanced:
    """Advanced tests for WorkQueue."""

    def test_priority_ordering(self):
        """Test that tasks are ordered by priority."""
        queue = WorkQueue()

        queue.add_task(function_address=0x1000, priority=1)
        queue.add_task(function_address=0x2000, priority=5)
        queue.add_task(function_address=0x3000, priority=3)

        ready = queue.get_ready_tasks()

        expect(ready[0].priority == _EXPECTED_READY_0_PRIORITY_5)
        expect(ready[1].priority == _EXPECTED_READY_1_PRIORITY_3)
        expect(ready[2].priority == 1)

    def test_max_tasks_limit(self):
        """Test max tasks limit in get_ready_tasks."""
        queue = WorkQueue()

        for i in range(10):
            queue.add_task(function_address=0x1000 + i * 0x100)

        ready = queue.get_ready_tasks(max_tasks=5)

        expect(len(ready) == _EXPECTED_LEN_READY_5)

    def test_get_dependencies(self):
        """Test getting dependencies."""
        queue = WorkQueue()

        id1 = queue.add_task(function_address=0x1000)
        id2 = queue.add_task(function_address=0x2000, dependencies=[id1, 0])

        deps = queue.get_dependencies(id2)

        expect(not (id1 not in deps))
        expect(not (0 not in deps))


class TestResultMergerAdvanced:
    """Advanced tests for ResultMerger."""

    def test_merge_empty_results(self):
        """Test merging empty results."""
        merger = ResultMerger()
        merged = merger.merge(None, [])

        expect(merged["total_functions"] == 0)
        expect(merged["successful"] == 0)
        expect(merged["failed"] == 0)

    def test_conflict_detection_different_functions(self):
        """Test that conflicts are detected per function."""
        merger = ResultMerger()

        results = [
            MutationResult(1, 0x1000, "f1", True, mutations_applied=[{"address": 0x1000, "size": 20}]),
            MutationResult(2, 0x2000, "f2", True, mutations_applied=[{"address": 0x1005, "size": 10}]),
        ]

        conflicts = merger.detect_conflicts(results)

        expect(len(conflicts) == 0)
