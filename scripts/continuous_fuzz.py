#!/usr/bin/env python3
"""Run deterministic parser, VM, relocation, assembler, and rewrite fuzzing."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import struct
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path

from r2morph.core import randomness
from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter_models import CodePatch, RewriteOperation
from r2morph.devirtualization.binary_rewriter_planning import (
    calculate_address_shifts,
    plan_rewrite_strategy,
    validate_patches,
)
from r2morph.mutations.code_virtualization_dispatch import bytecode_position_mask, decode_block
from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from r2morph.mutations.code_virtualization_engine_encoder import encode_bytecode
from r2morph.mutations.code_virtualization_engine_models import VirtualizedOp
from r2morph.platform.elf_handler_parsing import parse_elf_header
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler_parsing import read_pe_header
from r2morph.relocations.manager import RelocationManager

keystone = import_module("keystone")
KS_ARCH_X86 = keystone.KS_ARCH_X86
KS_MODE_64 = keystone.KS_MODE_64
Ks = keystone.Ks
KsError = keystone.KsError

_DEFAULT_CASES = 1000
_DEFAULT_MAX_PAYLOAD = 4096
_MAX_FAILURES = 128
_MIN_PATCH_ADDRESS = 0x1000
_ASSEMBLY_INSTRUCTION_COUNT = 4
_ASSEMBLY_INVALID_SAMPLE_RATE = 4
_VM_INTERPRETER_SAMPLE_INTERVAL = 128
_VM_INTERPRETER_ADDRESS = 0x401000
_VM_BYTECODE_BASE = 0x402000
_VM_BYTECODE_MAX_SIZE = 4096
_FUZZ_TARGETS = (
    "assembling",
    "binary_parsers",
    "elf_header_parser",
    "pe_header_parser",
    "macho_load_commands",
    "vm_dispatcher",
    "vm_bytecode",
    "relocations",
    "binary_rewriter",
)
_X86_64_ASSEMBLER = Ks(KS_ARCH_X86, KS_MODE_64)
_DATASET = Path(__file__).parents[1] / "fixtures" / "dataset"
_ELF_FIXTURE = _DATASET / "elf_x86_64"
_FORMAT_PARSER_FIXTURES = {
    "elf_header_parser": _ELF_FIXTURE,
    "pe_header_parser": _DATASET / "pe_x86_64.exe",
    "macho_load_commands": _DATASET / "macho_arm64",
}


class _ParserDiagnosticCounter(logging.Handler):
    def __init__(self, target: str, counts: dict[str, int]) -> None:
        super().__init__(level=logging.WARNING)
        self.target = target
        self.counts = counts

    def emit(self, record: logging.LogRecord) -> None:
        key = f"{self.target}.{record.levelname.lower()}"
        self.counts[key] = self.counts.get(key, 0) + 1


@dataclass(slots=True)
class _CampaignObservations:
    failures: list[dict[str, object]] = field(default_factory=list)
    target_runs: dict[str, int] = field(default_factory=lambda: dict.fromkeys(_FUZZ_TARGETS, 0))
    parser_diagnostic_counts: dict[str, int] = field(default_factory=dict)


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


def _assembly_case(seed: int, index: int) -> None:
    if index % _ASSEMBLY_INVALID_SAMPLE_RATE == 0:
        try:
            _X86_64_ASSEMBLER.asm(f"r2morph_invalid_{_bounded_value(seed, index, 35, 0xFFFF):x}")
        except KsError:
            return
        raise AssertionError("assembler accepted an invalid generated instruction")

    immediate = _bounded_value(seed, index, 32, 0x7FFFFFFF)
    stack_offset = _bounded_value(seed, index, 33, 0x7FF)
    assembly = (
        f"mov rax, 0x{_bounded_value(seed, index, 34, 0xFFFFFFFFFFFFFFFF):x}\n"
        f"add rax, 0x{immediate:x}\n"
        f"lea r10, [rsp+0x{stack_offset:x}]\n"
        f"xor r12d, 0x{immediate:x}\n"
    )
    encoded, instruction_count = _X86_64_ASSEMBLER.asm(assembly)
    if not encoded or instruction_count != _ASSEMBLY_INSTRUCTION_COUNT:
        raise AssertionError("assembler did not encode all generated instructions")


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


def _vm_bytecode_case(seed: int, index: int) -> None:
    case_seed = _bounded_value(seed, index, 36, 0xFFFFFFFF)
    scheme = build_vm_scheme(randomness.Random(case_seed))
    ops = [
        VirtualizedOp("mov", 0, _bounded_value(seed, index, 37, 0xFFFFFFFFFFFFFFFF), True, 64),
        VirtualizedOp("add", 0, _bounded_value(seed, index, 38, 0x7FFFFFFF), True, 64),
        VirtualizedOp("xor", 0, _bounded_value(seed, index, 39, 15), False, 64),
        VirtualizedOp("sub", 1, _bounded_value(seed, index, 40, 0x7FFFFFFF), True, 32),
    ]
    bytecode = encode_bytecode(ops, scheme, checksum=case_seed & 0xFF, bytecode_base=_VM_BYTECODE_BASE)
    if not bytecode or len(bytecode) > _VM_BYTECODE_MAX_SIZE:
        raise AssertionError("VM bytecode encoder returned an empty or oversized payload")
    # shortcut: sample interpreter assembly periodically to bound cost; widen coverage if codegen changes.
    if index % _VM_INTERPRETER_SAMPLE_INTERVAL == 0:
        assembly = _interpreter_asm(_VM_INTERPRETER_ADDRESS, scheme)
        encoded, instruction_count = _X86_64_ASSEMBLER.asm(assembly)
        if not encoded or instruction_count == 0:
            raise AssertionError("generated VM interpreter did not assemble")


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


def _macho_parser_case(path: Path, target: str, diagnostics: dict[str, int]) -> None:
    parser_logger = logging.getLogger("r2morph.platform.macho_handler")
    previous_propagate = parser_logger.propagate
    handler = _ParserDiagnosticCounter(target, diagnostics)
    parser_logger.addHandler(handler)
    parser_logger.propagate = False
    try:
        MachOHandler(path)._parse_macho_basic()
    finally:
        parser_logger.removeHandler(handler)
        parser_logger.propagate = previous_propagate


def _parser_case(payload: bytes, diagnostics: dict[str, int]) -> None:
    with tempfile.TemporaryDirectory(prefix="r2morph-fuzz-") as directory:
        path = Path(directory) / "candidate"
        path.write_bytes(payload)
        parse_elf_header(path)
        read_pe_header(path)
        _macho_parser_case(path, "binary_parsers", diagnostics)


def _format_parser_case(
    format_name: str,
    seed: int,
    index: int,
    payload: bytes,
    diagnostics: dict[str, int],
) -> None:
    fixture = _FORMAT_PARSER_FIXTURES[format_name].read_bytes()
    start, end = _parser_mutation_bounds(format_name, fixture)
    mutation_offset = start + _bounded_value(seed, index, 41, end - start - 1)
    mutation = payload[0] if payload and payload[0] else _bounded_value(seed, index, 42, 255) or 1
    mutated = bytearray(fixture)
    mutated[mutation_offset] ^= mutation

    with tempfile.TemporaryDirectory(prefix="r2morph-fuzz-") as directory:
        path = Path(directory) / "candidate"
        path.write_bytes(mutated)
        if format_name == "elf_header_parser":
            parse_elf_header(path)
        elif format_name == "pe_header_parser":
            read_pe_header(path)
        else:
            _macho_parser_case(path, format_name, diagnostics)


def _parser_mutation_bounds(format_name: str, fixture: bytes) -> tuple[int, int]:
    if format_name == "elf_header_parser":
        return 16, min(64, len(fixture))
    if format_name == "pe_header_parser":
        optional_header_offset = struct.unpack_from("<I", fixture, 0x3C)[0] + 24
        return optional_header_offset, min(optional_header_offset + 240, len(fixture))
    return 16, min(256, len(fixture))


def _case_targets(
    payload: bytes,
    seed: int,
    index: int,
    parser_diagnostics: dict[str, int],
) -> tuple[tuple[str, Callable[[], None]], ...]:
    return (
        ("assembling", lambda: _assembly_case(seed, index)),
        ("binary_parsers", lambda: _parser_case(payload, parser_diagnostics)),
        (
            "elf_header_parser",
            lambda: _format_parser_case("elf_header_parser", seed, index, payload, parser_diagnostics),
        ),
        (
            "pe_header_parser",
            lambda: _format_parser_case("pe_header_parser", seed, index, payload, parser_diagnostics),
        ),
        (
            "macho_load_commands",
            lambda: _format_parser_case("macho_load_commands", seed, index, payload, parser_diagnostics),
        ),
        ("vm_dispatcher", lambda: _dispatcher_case(seed, index)),
        ("vm_bytecode", lambda: _vm_bytecode_case(seed, index)),
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
    observations: _CampaignObservations,
) -> None:
    for target, action in _case_targets(payload, seed, index, observations.parser_diagnostic_counts):
        observations.target_runs[target] += 1
        try:
            action()
        except Exception as error:  # Fuzz boundary records unexpected failures for triage.
            _record_failure(observations.failures, target, payload, index, error)


def run_campaign(
    cases: int = _DEFAULT_CASES, seed: int = 20260827, max_payload: int = _DEFAULT_MAX_PAYLOAD
) -> dict[str, object]:
    """Exercise every fuzz target with bounded generated inputs."""
    if cases < 1:
        raise ValueError("cases must be positive")
    if max_payload < 1:
        raise ValueError("max_payload must be positive")

    observations = _CampaignObservations()
    for index in range(cases):
        payload = _payload(seed, index, max_payload)
        _exercise_case(payload, seed, index, observations)

    return {
        "schema_version": 1,
        "seed": seed,
        "cases": cases,
        "max_payload": max_payload,
        "target_runs": observations.target_runs,
        "parser_diagnostic_counts": dict(sorted(observations.parser_diagnostic_counts.items())),
        "failures": observations.failures,
        "failure_count": len(observations.failures),
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
