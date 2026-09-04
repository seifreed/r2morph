#!/usr/bin/env python3
"""Run deterministic parser, VM dispatch, relocation, and rewrite fuzzing."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections.abc import Callable
from pathlib import Path

from keystone import KS_ARCH_X86, KS_MODE_64, Ks

from r2morph.core import randomness
from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter_models import CodePatch, RewriteOperation
from r2morph.devirtualization.binary_rewriter_planning import (
    calculate_address_shifts,
    plan_rewrite_strategy,
    validate_patches,
)
from r2morph.mutations.code_virtualization_dispatch import bytecode_position_mask, decode_block
from r2morph.platform.elf_handler_parsing import parse_elf_header
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler_parsing import read_pe_header
from r2morph.relocations.manager import RelocationManager

_DEFAULT_CASES = 1000
_DEFAULT_MAX_PAYLOAD = 4096
_MAX_FAILURES = 128
_MIN_PATCH_ADDRESS = 0x1000
_FUZZ_TARGETS = ("binary_parsers", "vm_dispatcher", "relocations", "binary_rewriter")
_X86_64_ASSEMBLER = Ks(KS_ARCH_X86, KS_MODE_64)
_ELF_FIXTURE = Path(__file__).parents[1] / "fixtures" / "dataset" / "elf_x86_64"


def _bounded_value(seed: int, index: int, slot: int, maximum: int) -> int:
    digest = hashlib.sha256(f"{seed}:{index}:{slot}".encode("ascii")).digest()
    return int.from_bytes(digest[:8], "little") % (maximum + 1)


def _payload(seed: int, index: int, maximum: int) -> bytes:
    size = _bounded_value(seed, index, 0, maximum)
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(f"{seed}:{index}:{counter}".encode("ascii")).digest())
        counter += 1
    return bytes(output[:size])


def _rewrite_patches(seed: int, index: int) -> list[CodePatch]:
    operations = tuple(RewriteOperation)
    return [
        CodePatch(
            address=_bounded_value(seed, index, patch_index, 0xFF000) + _MIN_PATCH_ADDRESS,
            operation=operations[_bounded_value(seed, index, patch_index + 16, len(operations) - 1)],
            original_bytes=b"\x90",
            new_bytes=_payload(seed, index + patch_index, 32),
            size_change=_bounded_value(seed, index, patch_index + 8, 64) - 32,
        )
        for patch_index in range(index % 8)
    ]


def _rewrite_case(seed: int, index: int) -> None:
    patches = _rewrite_patches(seed, index)
    strategy = plan_rewrite_strategy(patches)
    shifts = calculate_address_shifts(patches)
    validation = validate_patches(
        patches,
        lambda address: address >= _MIN_PATCH_ADDRESS,
        bool,
    )

    addresses = [patch.address for patch in patches]
    if [patch.address for patch in strategy["patch_order"]] != sorted(addresses):
        raise AssertionError("rewrite planner did not order patches")
    if len(addresses) == len(set(addresses)) and (not validation["valid"] or len(shifts) != len(patches)):
        raise AssertionError("rewrite validation rejected non-overlapping patches")


def _dispatcher_case(seed: int, index: int) -> None:
    case_seed = _bounded_value(seed, index, 24, 0xFFFFFFFF)
    opcode_key = _bounded_value(seed, index, 29, 0xFF)
    table_keys = (_bounded_value(seed, index, 30, 0x7FFFFFFF), _bounded_value(seed, index, 31, 0x7FFFFFFF))
    opcode_xors = [f"  xor al, 0x{opcode_key:x}\n", "  xor al, r13b\n", "  xor al, byte ptr [rsp+0x88]\n"]
    table_xors = [f"  xor eax, 0x{key:x}\n" for key in table_keys]
    assembly = decode_block(
        opcode_xors=opcode_xors,
        bounds="  cmp al, 0xd\n  jae vm_exit\n",
        table_load="  lea r14, [rip+vm_table]\n  mov eax, dword ptr [r14+rax*4]\n",
        table_xors=table_xors,
        rng=randomness.Random(case_seed),
    )

    transfer_count = assembly.count("jmp rax") + assembly.count("push rax")
    required_fragments = (*opcode_xors, *table_xors, "byte ptr [rsi]", "vm_table")
    if transfer_count != 1 or any(fragment not in assembly for fragment in required_fragments):
        raise AssertionError("VM dispatcher lost a decode or transfer component")
    if bytecode_position_mask(index) != bytecode_position_mask(index & 0xFF):
        raise AssertionError("VM dispatcher position mask lost its byte cycle")
    encoded, _ = _X86_64_ASSEMBLER.asm(assembly + "vm_exit:\n  ret\nvm_table:\n  .long 0\n")
    if not encoded:
        raise AssertionError("VM dispatcher did not assemble")


def _relocation_case(seed: int, index: int) -> None:
    old_address = _bounded_value(seed, index, 25, 0xFFFFF) + _MIN_PATCH_ADDRESS
    new_address = _bounded_value(seed, index, 26, 0xFFFFF) + 0x200000
    size = _bounded_value(seed, index, 27, 0xFFF) + 1
    offset = _bounded_value(seed, index, 28, size - 1)
    manager = RelocationManager(Binary(_ELF_FIXTURE))
    manager.add_relocation(old_address, new_address, size)

    if manager.get_new_address(old_address + offset) != new_address + offset:
        raise AssertionError("relocation did not preserve the interior offset")
    if manager.get_new_address(old_address + size) is not None:
        raise AssertionError("relocation leaked beyond its half-open range")


def _parser_case(payload: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="r2morph-fuzz-") as directory:
        path = Path(directory) / "candidate"
        path.write_bytes(payload)
        parse_elf_header(path)
        read_pe_header(path)
        MachOHandler(path)._parse_macho_basic()


def _case_targets(payload: bytes, seed: int, index: int) -> tuple[tuple[str, Callable[[], None]], ...]:
    return (
        ("binary_parsers", lambda: _parser_case(payload)),
        ("vm_dispatcher", lambda: _dispatcher_case(seed, index)),
        ("relocations", lambda: _relocation_case(seed, index)),
        ("binary_rewriter", lambda: _rewrite_case(seed, index)),
    )


def _record_failure(
    failures: list[dict[str, object]], target: str, payload: bytes, index: int, error: Exception
) -> None:
    if len(failures) >= _MAX_FAILURES:
        return
    failures.append(
        {
            "case": index,
            "target": target,
            "input_sha256": hashlib.sha256(payload).hexdigest(),
            "input_size": len(payload),
            "error_type": type(error).__name__,
        }
    )


def _exercise_case(
    payload: bytes,
    seed: int,
    index: int,
    failures: list[dict[str, object]],
    target_runs: dict[str, int],
) -> None:
    for target, action in _case_targets(payload, seed, index):
        target_runs[target] += 1
        try:
            action()
        except Exception as error:  # Fuzz boundary records unexpected failures for triage.
            _record_failure(failures, target, payload, index, error)


def run_campaign(
    cases: int = _DEFAULT_CASES, seed: int = 20260827, max_payload: int = _DEFAULT_MAX_PAYLOAD
) -> dict[str, object]:
    """Exercise every fuzz target with bounded generated inputs."""
    if cases < 1:
        raise ValueError("cases must be positive")
    if max_payload < 1:
        raise ValueError("max_payload must be positive")

    failures: list[dict[str, object]] = []
    target_runs = dict.fromkeys(_FUZZ_TARGETS, 0)
    for index in range(cases):
        payload = _payload(seed, index, max_payload)
        _exercise_case(payload, seed, index, failures, target_runs)

    return {
        "schema_version": 1,
        "seed": seed,
        "cases": cases,
        "max_payload": max_payload,
        "target_runs": target_runs,
        "failures": failures,
        "failure_count": len(failures),
        "failure_limit": _MAX_FAILURES,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=_DEFAULT_CASES)
    parser.add_argument("--seed", type=int, default=20260827)
    parser.add_argument("--max-payload", type=int, default=_DEFAULT_MAX_PAYLOAD)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run_campaign(args.cases, args.seed, args.max_payload)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["failure_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
