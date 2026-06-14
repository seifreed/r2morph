"""Stage execution helpers for parallel mutation scheduling."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any

from r2morph.core.parallel_planner import PassResult, PassStatus
from r2morph.protocols import MutationPassProtocol


def execute_stage(
    stage: list[str],
    passes: list[MutationPassProtocol],
    *,
    max_workers: int,
    execute_pass: Callable[[MutationPassProtocol, Callable[[str, float], None] | None], PassResult],
    progress_callback: Callable[[str, float], None] | None,
) -> dict[str, PassResult]:
    """Execute all passes in a stage in parallel."""
    results: dict[str, PassResult] = {}
    pass_map = {p.name: p for p in passes}

    with ThreadPoolExecutor(max_workers=min(max_workers, len(stage))) as executor:
        futures: dict[Future[Any], str] = {}

        for pass_name in stage:
            if pass_name not in pass_map:
                continue
            pass_obj = pass_map[pass_name]
            future = executor.submit(
                execute_pass,
                pass_obj,
                progress_callback,
            )
            futures[future] = pass_name

        for future in as_completed(futures):
            pass_name = futures[future]
            try:
                result = future.result()
                results[pass_name] = result
            except Exception as exc:
                results[pass_name] = PassResult(
                    pass_name=pass_name,
                    status=PassStatus.FAILED,
                    error=str(exc),
                )

    return results
