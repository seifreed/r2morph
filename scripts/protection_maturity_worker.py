"""Isolate and supervise one protection maturity fixture worker."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from r2morph.adapters.process import ProcessContext, ProcessResult, ProcessTimeoutError, run_process

_WORKER_GRACE_SECONDS = 5.0


def run_supervised_command(command: Sequence[str], timeout: float, input_bytes: bytes, cwd: Path) -> ProcessResult:
    """Run a command with a deadline that also terminates its process tree."""
    return run_process(
        command,
        timeout=timeout,
        context=ProcessContext(input_bytes=input_bytes, cwd=cwd),
    )


def run_fixture_worker(
    task: tuple[Path, range, Path, tuple[str, ...], tuple[tuple[str, ...], ...], float],
) -> tuple[tuple[str, dict[str, object]], ...]:
    """Run a fixture in a process group so a hard timeout also kills its children."""
    fixture, seeds, output_root, pass_names, runtime_inputs, timeout_seconds = task
    payload = {
        "fixture": str(fixture),
        "seed_start": seeds.start,
        "seed_stop": seeds.stop,
        "output_root": str(output_root),
        "pass_names": pass_names,
        "runtime_inputs": runtime_inputs,
        "timeout_seconds": timeout_seconds,
    }
    worker_script = Path(__file__).with_name("protection_maturity_baseline.py")
    command = [sys.executable, str(worker_script), "--_worker-task"]
    try:
        result = run_supervised_command(
            command,
            timeout_seconds + _WORKER_GRACE_SECONDS,
            json.dumps(payload).encode(),
            Path(__file__).resolve().parents[1],
        )
    except ProcessTimeoutError:
        raise FixtureWorkerTimeoutError(f"fixture {fixture.name!r} exceeded the hard worker timeout") from None
    if result.returncode != 0:
        raise RuntimeError(f"fixture worker for {fixture.name!r} exited with status {result.returncode}")
    response = cast(dict[str, object], json.loads(result.stdout))
    if response.get("status") == "timeout":
        raise FixtureWorkerTimeoutError(str(response["error"]))
    raw_results = cast(list[list[object]], response["results"])
    return tuple((str(item[0]), cast(dict[str, object], item[1])) for item in raw_results)


class FixtureWorkerTimeoutError(TimeoutError):
    """A fixture exceeded either its cooperative or hard worker deadline."""
