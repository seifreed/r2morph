#!/usr/bin/env python3
"""Record reproducible corpus, runtime, and virtualization measurements."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import shlex
import shutil
import struct
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code

_ELF_MAGIC = b"\x7fELF"
_ET_EXEC = 2
_ET_DYN = 3
_EM_X86_64 = 62
_ELFCLASS64 = 2
_BITS_64 = 64
_ELF_IDENT_HEADER_BYTES = 20
_RUNTIME_TIMEOUT_SECONDS = 5.0
_PREVIEW_BYTES = 32


class _ArtifactAccumulator:
    """Hash a process stream incrementally while retaining only its preview."""

    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._preview = bytearray()
        self._size = 0

    def update(self, chunk: bytes) -> None:
        self._digest.update(chunk)
        self._size += len(chunk)
        remaining = _PREVIEW_BYTES - len(self._preview)
        if remaining > 0:
            self._preview.extend(chunk[:remaining])

    def result(self) -> dict[str, object]:
        return {
            "sha256": self._digest.hexdigest(),
            "size": self._size,
            "preview_hex": bytes(self._preview).hex(),
        }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_artifact(value: bytes) -> dict[str, object]:
    accumulator = _ArtifactAccumulator()
    accumulator.update(value)
    return accumulator.result()


def _snapshot_created_files(directory: Path) -> dict[str, dict[str, object]]:
    """Return bounded hashes and sizes for files created in a runtime directory."""
    files: dict[str, dict[str, object]] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != "program":
            files[path.relative_to(directory).as_posix()] = {
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
    return files


def _runtime_command(path: Path) -> list[str]:
    with path.open("rb") as handle:
        first_line = handle.readline(4096)
    if not first_line.startswith(b"#!"):
        return [str(path)]
    interpreter = shlex.split(first_line[2:].decode("utf-8", errors="replace"))
    return [*interpreter, str(path)] if interpreter else [str(path)]


async def _capture_runtime_stream(stream: asyncio.StreamReader) -> dict[str, object]:
    accumulator = _ArtifactAccumulator()
    while chunk := await stream.read(4096):
        accumulator.update(chunk)
    return accumulator.result()


async def _run_runtime(command: list[str], workdir: Path) -> dict[str, object]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as error:
        return {
            "status": "error",
            "error_type": type(error).__name__,
            "stdout": _digest_artifact(b""),
            "stderr": _digest_artifact(b""),
        }
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("Runtime process did not expose captured streams")
    stdout_task = asyncio.create_task(_capture_runtime_stream(process.stdout))
    stderr_task = asyncio.create_task(_capture_runtime_stream(process.stderr))
    try:
        return_code = await asyncio.wait_for(process.wait(), _RUNTIME_TIMEOUT_SECONDS)
    except TimeoutError:
        process.kill()
        await process.wait()
        await asyncio.gather(stdout_task, stderr_task)
        return {"status": "timeout", "stdout": stdout_task.result(), "stderr": stderr_task.result()}
    stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
    return {"status": "completed", "return_code": return_code, "stdout": stdout, "stderr": stderr}


def _runtime_artifacts(path: Path) -> dict[str, object]:
    """Run a fixture in isolation and retain bounded, reproducible observables."""
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r2morph-runtime-") as temporary:
        workdir = Path(temporary)
        runtime_path = workdir / "program"
        shutil.copyfile(path, runtime_path)
        runtime_path.chmod(0o700)
        result = asyncio.run(_run_runtime(_runtime_command(runtime_path), workdir))
        result["duration_seconds"] = time.perf_counter() - started
        result["created_files"] = _snapshot_created_files(workdir)
        return result


def _command_count(binary: Binary, command: str) -> int:
    value = binary.r2.cmdj(command)
    return len(value) if isinstance(value, list) else 0


def _static_metrics(binary: Binary) -> dict[str, object]:
    started = time.perf_counter()
    binary.analyze("aa")
    functions = binary.get_functions()
    basic_blocks = 0
    cfg_edges = 0
    instructions = 0
    for function in functions:
        address = function.get("addr")
        if not isinstance(address, int):
            continue
        blocks = binary.get_basic_blocks(address)
        basic_blocks += len(blocks)
        cfg_edges += sum(
            1
            for block in blocks
            for edge_name in ("jump", "fail")
            if isinstance(block.get(edge_name), int) and block[edge_name] >= 0
        )
        instructions += len(binary.get_function_disasm(address))

    info = binary.info.get("bin", {})
    raw_arch = str(info.get("arch", "unknown"))
    bits = int(info.get("bits", 0) or 0)
    architecture = "x86_64" if raw_arch in {"x86", "x64"} and bits == _BITS_64 else raw_arch
    return {
        "format": str(info.get("bintype", "unknown")).upper(),
        "architecture": architecture,
        "bits": bits,
        "number_of_functions": len(functions),
        "number_of_basic_blocks": basic_blocks,
        "number_of_cfg_edges": cfg_edges,
        "number_of_instructions": instructions,
        "number_of_strings": _command_count(binary, "izj"),
        "number_of_imports": _command_count(binary, "iij"),
        "number_of_references": _command_count(binary, "axlj"),
        "analysis_duration_seconds": time.perf_counter() - started,
    }


def _inspect(path: Path) -> dict[str, object]:
    binary = Binary(path)
    binary.open()
    try:
        return _static_metrics(binary)
    finally:
        binary.close()


def _safe_inspect(path: Path) -> dict[str, object]:
    try:
        return {"status": "completed", "metrics": _inspect(path)}
    except Exception as error:  # Measurement boundary records per-artifact failures.
        return {"status": "error", "error_type": type(error).__name__}


def _semantic_artifacts(path: Path) -> dict[str, object]:
    started = time.perf_counter()
    try:
        exit_code = emulate_exit_code(path)
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        return {
            "status": "error",
            "error_type": type(error).__name__,
            "error": str(error),
            "duration_seconds": time.perf_counter() - started,
        }
    return {
        "status": "completed" if exit_code is not None else "no_exit_syscall",
        "exit_code": exit_code,
        "duration_seconds": time.perf_counter() - started,
    }


def _runtime_observables_equal(expected: object, actual: object) -> bool:
    """Compare bounded native-runtime observables without retaining raw output."""
    if (
        not isinstance(expected, Mapping)
        or not isinstance(actual, Mapping)
        or expected.get("status") != "completed"
        or actual.get("status") != "completed"
    ):
        return False
    for field in ("status", "return_code", "error_type"):
        if expected.get(field) != actual.get(field):
            return False
    for stream in ("stdout", "stderr"):
        expected_digest = expected.get(stream)
        actual_digest = actual.get(stream)
        if not isinstance(expected_digest, Mapping) or not isinstance(actual_digest, Mapping):
            return False
        if expected_digest.get("sha256") != actual_digest.get("sha256"):
            return False
        if expected_digest.get("size") != actual_digest.get("size"):
            return False
    return expected.get("created_files") == actual.get("created_files")


def _semantic_run_matches(baseline: object, baseline_runtime: object, run: object) -> bool:
    """Require valid emulator parity and identical bounded runtime observables."""
    if not isinstance(baseline, Mapping) or not isinstance(baseline_runtime, Mapping):
        return False
    if not isinstance(run, Mapping) or run.get("status") != "passed":
        return False
    if baseline.get("status") != "completed":
        return False
    unicorn = run.get("unicorn")
    if not isinstance(unicorn, Mapping) or unicorn.get("status") != "completed":
        return False
    if unicorn.get("exit_code") != baseline.get("exit_code"):
        return False
    return _runtime_observables_equal(baseline_runtime, run.get("runtime"))


def _transformation_evidence(status: str, stats: object, error: object = None) -> dict[str, object]:
    """Describe whether the selected pass changed the fixture and why not."""
    if status == "error":
        if isinstance(error, Mapping):
            reason = error.get("error") or error.get("error_type") or "transformation failed"
        else:
            reason = "transformation failed"
        return {"pass_name": "code-virtualization", "status": "error", "reason": str(reason)}

    if not isinstance(stats, Mapping):
        return {"pass_name": "code-virtualization", "status": "omitted", "reason": "no pass statistics"}
    virtualized = stats.get("functions_virtualized")
    if isinstance(virtualized, int) and virtualized > 0:
        return {
            "pass_name": "code-virtualization",
            "status": "applied",
            "functions_virtualized": virtualized,
        }
    diagnostics = stats.get("unsupported_functions")
    if isinstance(diagnostics, list) and diagnostics and isinstance(diagnostics[0], Mapping):
        capability = diagnostics[0].get("capability", "unsupported capability")
        reason = diagnostics[0].get("reason", "pass precondition was not met")
        return {
            "pass_name": "code-virtualization",
            "status": "omitted",
            "reason": f"{capability}: {reason}",
        }
    return {
        "pass_name": "code-virtualization",
        "status": "omitted",
        "reason": "no eligible function was virtualized",
    }


def _measure_seed(fixture: Path, seed: int, output_dir: Path) -> dict[str, object]:
    output = output_dir / f"seed-{seed}"
    shutil.copyfile(fixture, output)
    started = time.perf_counter()
    try:
        binary = Binary(output, writable=True)
        binary.open()
        try:
            stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": seed}).apply(binary)
            binary.save()
        finally:
            binary.close()
        status = "passed"
        error: dict[str, object] = {}
    except Exception as error_value:  # Measurement boundary records per-fixture failures.
        stats = {}
        status = "error"
        error = {"error_type": type(error_value).__name__, "error": str(error_value)}

    run: dict[str, object] = {
        "seed": seed,
        "status": status,
        "transformation": _transformation_evidence(status, stats, error if status == "error" else None),
        "output_sha256": sha256(output),
        "output_size": output.stat().st_size,
        "transform_duration_seconds": time.perf_counter() - started,
        "runtime": _runtime_artifacts(output),
        "unicorn": _semantic_artifacts(output),
    }
    if status == "passed":
        run.update(
            {
                "functions_virtualized": stats.get("functions_virtualized", 0),
                "total_instructions": stats.get("total_instructions", 0),
                "total_bytecode_bytes": stats.get("total_bytecode_bytes", 0),
                "after": _safe_inspect(output),
            }
        )
    else:
        run["error"] = error
    return run


def measure_fixture(fixture: Path, seeds: range, output_root: Path) -> dict[str, object]:
    baseline_runtime = _runtime_artifacts(fixture)
    baseline_unicorn = _semantic_artifacts(fixture)
    baseline = _safe_inspect(fixture)
    output_dir = output_root / fixture.name
    output_dir.mkdir()
    runs = [_measure_seed(fixture, seed, output_dir) for seed in seeds]
    semantic_runs = []
    for run in runs:
        runtime_equal = _runtime_observables_equal(baseline_runtime, run.get("runtime"))
        run["runtime_observable_equal"] = runtime_equal
        if _semantic_run_matches(baseline_unicorn, baseline_runtime, run):
            semantic_runs.append(run)
    return {
        "sample": fixture.name,
        "baseline_sha256": sha256(fixture),
        "baseline_size": fixture.stat().st_size,
        "baseline": baseline,
        "baseline_runtime": baseline_runtime,
        "baseline_unicorn": baseline_unicorn,
        "seeds": [run["seed"] for run in runs],
        "runs": runs,
        "all_semantic_equal": bool(runs) and len(semantic_runs) == len(runs),
        "successful_runs": len(semantic_runs),
        "failed_runs": len(runs) - len(semantic_runs),
    }


def discover_executables(dataset: Path) -> list[Path]:
    """Return supported ELF executable files, excluding source and relocatable objects."""
    executables: list[Path] = []
    for path in sorted(dataset.iterdir()):
        if not path.is_file():
            continue
        header = path.read_bytes()[:_ELF_IDENT_HEADER_BYTES]
        if len(header) < _ELF_IDENT_HEADER_BYTES or header[:4] != _ELF_MAGIC or header[4] != _ELFCLASS64:
            continue
        elf_type, machine = struct.unpack_from("<HH", header, 16)
        if elf_type in {_ET_EXEC, _ET_DYN} and machine == _EM_X86_64:
            executables.append(path)
    return executables


def _render_result(fixtures: list[dict[str, object]]) -> dict[str, object]:
    successful_seed_runs = sum(
        value if isinstance(value := fixture.get("successful_runs"), int) else 0 for fixture in fixtures
    )
    failed_seed_runs = sum(value if isinstance(value := fixture.get("failed_runs"), int) else 0 for fixture in fixtures)
    return {
        "schema_version": 2,
        "measurement": "protection-maturity-corpus",
        "compatible_fixture_count": len(fixtures),
        "fixtures": fixtures,
        "summary": {
            "semantic_passes": sum(1 for fixture in fixtures if fixture["all_semantic_equal"]),
            "semantic_failures": sum(1 for fixture in fixtures if not fixture["all_semantic_equal"]),
            "successful_seed_runs": successful_seed_runs,
            "failed_seed_runs": failed_seed_runs,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixtures", nargs="*", type=Path)
    parser.add_argument("--all", action="store_true", dest="all_fixtures")
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--first-seed", type=int, default=20260820)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    if args.all_fixtures and args.fixtures:
        parser.error("pass either --all or explicit fixture paths")
    fixtures = discover_executables(args.dataset) if args.all_fixtures else args.fixtures
    if not fixtures:
        parser.error("no executable fixtures selected")

    seeds = range(args.first_seed, args.first_seed + args.count)
    with tempfile.TemporaryDirectory(prefix="r2morph-maturity-") as temp_dir:
        measurements = [measure_fixture(fixture, seeds, Path(temp_dir)) for fixture in fixtures]
    rendered = json.dumps(_render_result(measurements), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
