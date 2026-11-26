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
from functools import lru_cache
from importlib import import_module
from pathlib import Path

import lief

from r2morph.core import randomness
from r2morph.core.assembly import AssemblyService
from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import BinaryRewriter
from r2morph.devirtualization.binary_rewriter_models import CodePatch, RewriteOperation
from r2morph.devirtualization.binary_rewriter_planning import (
    calculate_address_shifts,
    plan_rewrite_strategy,
    validate_patches,
)
from r2morph.mutations.code_virtualization_dispatch import bytecode_position_mask, decode_block
from r2morph.mutations.code_virtualization_engine import decode_instruction
from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import (
    GP_REGISTERS,
    REGISTER32_INDEX,
    REGISTER_INDEX,
    RSP_INDEX,
    SUPPORTED_MNEMONICS,
    build_vm_scheme,
    immediate_fits_width,
)
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
_VM_DECODER_CASE_COUNT = 4
_VM_DECODER_MNEMONICS = tuple(sorted(SUPPORTED_MNEMONICS))
_VM_DECODER_REGISTERS = tuple(
    (name, index, width)
    for registers, width in ((REGISTER_INDEX, 64), (REGISTER32_INDEX, 32))
    for name, index in registers.items()
    if index != RSP_INDEX
)
_FUZZ_TARGETS = (
    "assembling",
    "binary_parsers",
    "elf_header_parser",
    "pe_header_parser",
    "macho_load_commands",
    "vm_dispatcher",
    "vm_bytecode",
    "vm_instruction_decoder",
    "relocations",
    "binary_rewriter",
    "binary_rewriter_output",
)
# shortcut: samples every 32 inputs, widen after measuring full CI runner cost.
_REWRITER_OUTPUT_SAMPLE_INTERVAL = 32
_X86_64_ASSEMBLER = Ks(KS_ARCH_X86, KS_MODE_64)
_DATASET = Path(__file__).parents[1] / "fixtures" / "dataset"
_ELF_FIXTURE = _DATASET / "elf_x86_64"
_FORMAT_PARSER_FIXTURES = {
    "elf_header_parser": _ELF_FIXTURE,
    "pe_header_parser": _DATASET / "pe_x86_64.exe",
    "macho_load_commands": _DATASET / "macho_arm64",
}


class _FuzzRasm:
    def cmd(self, command: str) -> str:
        instruction = command.removeprefix('"pa ').removesuffix('"')
        try:
            encoded, _ = _X86_64_ASSEMBLER.asm(instruction)
        except KsError:
            return ""
        return bytes(encoded).hex()


class _FuzzAssemblyBinary:
    r2 = _FuzzRasm()

    @staticmethod
    def _resolve_symbolic_vars(instruction: str, function_addr: int | None = None) -> str:
        return instruction

    @staticmethod
    def get_arch_family() -> tuple[str, int]:
        return "x86_64", 64


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
    return [
        CodePatch(
            address=_bounded_value(seed, index, patch_index, 0xFF000) + _MIN_PATCH_ADDRESS,
            operation=RewriteOperation.INSTRUCTION_REPLACE,
            original_bytes=b"\x90",
            new_bytes=b"\xcc",
            size_change=0,
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

    buffer = bytearray(_payload(seed, index, 64) or b"\x00")
    offset = _bounded_value(seed, index, 31, len(buffer) - 1)
    before = bytes(buffer)
    patch = CodePatch(
        address=_MIN_PATCH_ADDRESS + offset,
        operation=RewriteOperation.INSTRUCTION_REPLACE,
        original_bytes=before[offset : offset + 1],
        new_bytes=bytes([before[offset] ^ 0xFF]),
        size_change=0,
    )
    rewriter = BinaryRewriter()
    rewriter.sections = {
        ".text": {
            "perm": "r-x",
            "vaddr": _MIN_PATCH_ADDRESS,
            "paddr": 0,
            "size": len(buffer),
            "vsize": len(buffer),
        }
    }
    rewriter._rewritten_bytes = buffer
    if not rewriter._apply_single_patch(patch):
        raise AssertionError("binary rewriter rejected a valid mapped replacement")
    if buffer[:offset] != before[:offset] or buffer[offset + 1 :] != before[offset + 1 :]:
        raise AssertionError("binary rewriter changed bytes outside the patch range")

    if rewriter._apply_single_patch(patch):
        raise AssertionError("binary rewriter accepted stale original bytes")

    invalid_address_patch = CodePatch(
        address=_MIN_PATCH_ADDRESS + len(buffer),
        operation=RewriteOperation.INSTRUCTION_REPLACE,
        original_bytes=b"\x00",
        new_bytes=b"\xff",
        size_change=0,
    )
    if rewriter._apply_single_patch(invalid_address_patch):
        raise AssertionError("binary rewriter accepted an address outside file-backed code")

    safe_offset = (offset + 1) % len(buffer)
    non_executable_patch = CodePatch(
        address=_MIN_PATCH_ADDRESS + safe_offset,
        operation=RewriteOperation.INSTRUCTION_REPLACE,
        original_bytes=bytes([buffer[safe_offset]]),
        new_bytes=bytes([buffer[safe_offset] ^ 0xFF]),
        size_change=0,
    )
    rewriter.sections[".text"]["perm"] = "r--"
    if rewriter._apply_single_patch(non_executable_patch):
        raise AssertionError("binary rewriter accepted a non-executable section")


@lru_cache(maxsize=1)
def _elf_text_mapping() -> tuple[int, int, int]:
    parsed = lief.parse(str(_ELF_FIXTURE))
    section = parsed.get_section(".text") if parsed is not None else None
    if section is None or section.size < 1:
        raise AssertionError("fuzz ELF fixture has no file-backed .text section")
    return int(section.virtual_address), int(section.offset), int(section.size)


class _FuzzELFAnalyzer:
    def __init__(self, virtual_address: int, file_offset: int, size: int) -> None:
        self._section = {
            "name": ".text",
            "perm": "r-x",
            "vaddr": virtual_address,
            "paddr": file_offset,
            "size": size,
            "vsize": size,
        }

    def cmdj(self, command: str) -> object:
        if command == "ij":
            return {"bin": {"class": "ELF64", "arch": "x86", "bits": 64, "endian": "little"}}
        if command == "iSj":
            return [self._section]
        if command == "irj":
            return []
        raise AssertionError(f"unexpected analyzer command: {command}")


class _FuzzELFBinary:
    def __init__(self, path: Path, virtual_address: int, file_offset: int, size: int) -> None:
        self.filepath = path
        self.r2 = _FuzzELFAnalyzer(virtual_address, file_offset, size)


def _rewrite_output_case(seed: int, index: int) -> None:
    virtual_address, file_offset, section_size = _elf_text_mapping()
    offset = _bounded_value(seed, index, 49, section_size - 1)
    original = _ELF_FIXTURE.read_bytes()
    old_byte = original[file_offset + offset]
    replacement = old_byte ^ (_bounded_value(seed, index, 50, 0xFF) or 1)
    patch = CodePatch(
        address=virtual_address + offset,
        operation=RewriteOperation.INSTRUCTION_REPLACE,
        original_bytes=bytes([old_byte]),
        new_bytes=bytes([replacement]),
    )

    with tempfile.TemporaryDirectory(prefix="r2morph-rewrite-fuzz-") as directory:
        output = Path(directory) / "rewritten.elf"
        rewriter = BinaryRewriter(_FuzzELFBinary(_ELF_FIXTURE, virtual_address, file_offset, section_size))
        result = rewriter.rewrite_binary(str(output), [patch], preserve_original=False)
        if not result.success or result.patches_applied != 1 or not result.integrity_checks.get("file_exists"):
            raise AssertionError(f"full binary rewrite failed: {result.errors}")

        expected = bytearray(original)
        expected[file_offset + offset] = replacement
        if output.read_bytes() != expected:
            raise AssertionError("full binary rewrite changed bytes outside the requested patch")
        reparsed = lief.parse(str(output))
        if reparsed is None or reparsed.get_section(".text") is None:
            raise AssertionError("full binary rewrite output is not a parseable ELF")


def _assembly_case(seed: int, index: int) -> None:
    if index % _ASSEMBLY_INVALID_SAMPLE_RATE == 0:
        instruction = f"r2morph_invalid_{_bounded_value(seed, index, 35, 0xFFFF):x}"
        try:
            _X86_64_ASSEMBLER.asm(instruction)
        except KsError as error:
            service_logger = logging.getLogger("r2morph.core.assembly")
            previous_level = service_logger.level
            service_logger.setLevel(logging.CRITICAL + 1)
            try:
                service_encoded = AssemblyService().assemble(_FuzzAssemblyBinary(), instruction)
            finally:
                service_logger.setLevel(previous_level)
            if service_encoded is not None:
                raise AssertionError("assembly service accepted an invalid generated instruction") from error
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
    service_encoded = AssemblyService().assemble(_FuzzAssemblyBinary(), assembly)
    if service_encoded != bytes(encoded):
        raise AssertionError("assembly service output differs from the generated valid instruction sequence")


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
    exit_position = len(bytecode) - 1
    decoded_exit_opcode = bytecode[exit_position] ^ (case_seed & 0xFF) ^ bytecode_position_mask(exit_position)
    if decoded_exit_opcode != scheme.exit_opcode:
        raise AssertionError("VM bytecode checksum or position mask corrupted the exit opcode")
    # shortcut: sample interpreter assembly periodically to bound cost; widen coverage if codegen changes.
    if index % _VM_INTERPRETER_SAMPLE_INTERVAL == 0:
        assembly = _interpreter_asm(_VM_INTERPRETER_ADDRESS, scheme)
        encoded, instruction_count = _X86_64_ASSEMBLER.asm(assembly)
        if not encoded or instruction_count == 0:
            raise AssertionError("generated VM interpreter did not assemble")


def _vm_instruction_decoder_case(seed: int, index: int, payload: bytes) -> None:
    case_kind = _bounded_value(seed, index, 43, _VM_DECODER_CASE_COUNT - 1)
    mnemonic = _VM_DECODER_MNEMONICS[_bounded_value(seed, index, 44, len(_VM_DECODER_MNEMONICS) - 1)]
    dst_name, _, width = _VM_DECODER_REGISTERS[_bounded_value(seed, index, 45, len(_VM_DECODER_REGISTERS) - 1)]
    same_width_registers = tuple(register for register in _VM_DECODER_REGISTERS if register[2] == width)
    src_name, _, _ = same_width_registers[_bounded_value(seed, index, 46, len(same_width_registers) - 1)]
    immediate = _bounded_value(seed, index, 47, 0x7FFFFFFF)
    malformed_cases = (
        f"{mnemonic} rsp, {src_name}",
        f"{mnemonic} {dst_name}, [{src_name}]",
        f"{mnemonic} {dst_name}, {src_name}, {src_name}",
        f"{mnemonic} {dst_name}, {1 << 128}",
    )
    candidates = (
        payload.decode("utf-8", errors="replace"),
        f"{mnemonic} {dst_name}, {immediate}",
        f"{mnemonic} {dst_name}, {src_name}",
        malformed_cases[_bounded_value(seed, index, 48, len(malformed_cases) - 1)],
    )
    operation = decode_instruction(candidates[case_kind])
    if operation is None:
        return
    if (
        operation.mnemonic not in SUPPORTED_MNEMONICS
        or operation.dst_index < 0
        or operation.dst_index >= len(GP_REGISTERS)
        or operation.dst_index == RSP_INDEX
        or operation.width not in (32, 64)
    ):
        raise AssertionError("VM instruction decoder returned an invalid operation header")
    if operation.is_immediate:
        if not immediate_fits_width(operation.value, operation.width):
            raise AssertionError("VM instruction decoder returned an out-of-range immediate")
    elif operation.value < 0 or operation.value >= len(GP_REGISTERS) or operation.value == RSP_INDEX:
        raise AssertionError("VM instruction decoder returned an invalid source register")


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
    targets = (
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
        ("vm_instruction_decoder", lambda: _vm_instruction_decoder_case(seed, index, payload)),
        ("relocations", lambda: _relocation_case(seed, index)),
        ("binary_rewriter", lambda: _rewrite_case(seed, index)),
    )
    if index % _REWRITER_OUTPUT_SAMPLE_INTERVAL == 0:
        return (*targets, ("binary_rewriter_output", lambda: _rewrite_output_case(seed, index)))
    return targets


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
