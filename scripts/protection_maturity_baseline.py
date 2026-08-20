#!/usr/bin/env python3
"""Record reproducible corpus, runtime, and virtualization measurements."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import select
import shutil
import struct
import tempfile
import time
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
_SIGKILL = 9
_RUNTIME_TIMEOUT_SECONDS = 5.0
_PREVIEW_BYTES = 32


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest_artifact(value: bytes) -> dict[str, object]:
    return {
        "sha256": hashlib.sha256(value).hexdigest(),
        "size": len(value),
        "preview_hex": value[:_PREVIEW_BYTES].hex(),
    }


def _prepare_runtime_path(path: Path) -> tuple[Path, Path | None]:
    if os.access(path, os.X_OK):
        return path, None
    descriptor, staged_name = tempfile.mkstemp(prefix="r2morph-runtime-")
    os.close(descriptor)
    staged = Path(staged_name)
    shutil.copyfile(path, staged)
    staged.chmod(0o700)
    return staged, staged


def _runtime_artifacts(path: Path) -> dict[str, object]:
    """Run a synthetic fixture natively and retain bounded, reproducible output."""
    started = time.perf_counter()
    runtime_path, staged_path = _prepare_runtime_path(path)
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    try:
        pid = os.posix_spawn(
            str(runtime_path),
            [str(runtime_path)],
            os.environ.copy(),
            file_actions=[
                (os.POSIX_SPAWN_DUP2, stdout_write, 1),
                (os.POSIX_SPAWN_DUP2, stderr_write, 2),
                (os.POSIX_SPAWN_CLOSE, stdout_read),
                (os.POSIX_SPAWN_CLOSE, stderr_read),
                (os.POSIX_SPAWN_CLOSE, stdout_write),
                (os.POSIX_SPAWN_CLOSE, stderr_write),
            ],
        )
    except OSError as error:
        for descriptor in (stdout_read, stdout_write, stderr_read, stderr_write):
            os.close(descriptor)
        if staged_path is not None:
            staged_path.unlink()
        return {
            "status": "error",
            "error_type": type(error).__name__,
            "duration_seconds": time.perf_counter() - started,
            "stdout": _digest_artifact(b""),
            "stderr": _digest_artifact(b""),
        }
    os.close(stdout_write)
    os.close(stderr_write)

    streams = {stdout_read: bytearray(), stderr_read: bytearray()}
    captured = {stdout_read: bytearray(), stderr_read: bytearray()}
    timed_out = False
    deadline = time.perf_counter() + _RUNTIME_TIMEOUT_SECONDS
    while streams:
        ready, _, _ = select.select(list(streams), [], [], max(0.0, deadline - time.perf_counter()))
        if not ready:
            timed_out = True
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, _SIGKILL)
            ready = list(streams)
        for descriptor in ready:
            chunk = os.read(descriptor, 4096)
            if chunk:
                captured[descriptor].extend(chunk)
            else:
                os.close(descriptor)
                del streams[descriptor]
        if timed_out and streams:
            _, _, _ = select.select(list(streams), [], [], 0.1)

    wait_status = os.waitpid(pid, 0)[1]
    result: dict[str, object] = {
        "status": "timeout" if timed_out else "completed",
        "duration_seconds": time.perf_counter() - started,
        "stdout": _digest_artifact(bytes(captured[stdout_read])),
        "stderr": _digest_artifact(bytes(captured[stderr_read])),
    }
    if not timed_out:
        result["return_code"] = os.waitstatus_to_exitcode(wait_status)
    if staged_path is not None:
        staged_path.unlink()
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
    baseline_exit = baseline_unicorn.get("exit_code")
    semantic_runs = [run for run in runs if run.get("status") == "passed" and isinstance(run.get("unicorn"), dict)]
    semantic_exits = [
        unicorn.get("exit_code")
        for run in semantic_runs
        for unicorn in [run.get("unicorn")]
        if isinstance(unicorn, dict)
    ]
    return {
        "sample": fixture.name,
        "baseline_sha256": sha256(fixture),
        "baseline_size": fixture.stat().st_size,
        "baseline": baseline,
        "baseline_runtime": baseline_runtime,
        "baseline_unicorn": baseline_unicorn,
        "seeds": [run["seed"] for run in runs],
        "runs": runs,
        "all_semantic_equal": bool(semantic_runs) and all(exit_code == baseline_exit for exit_code in semantic_exits),
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
