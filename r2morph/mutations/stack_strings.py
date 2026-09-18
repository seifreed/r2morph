"""
Stack Strings - Hide static strings by constructing them on the stack.

Transforms static string literals into dynamic stack construction,
evading string detection in static analysis and making strings
harder to find in memory dumps.

Example transformation:

    Original:
        push "Hello"
        push "Hello World"
        call printf

    Transformed:
        sub rsp, 12       ; allocate space
        mov byte [rsp+0], 'H'
        mov byte [rsp+1], 'e'
        mov byte [rsp+2], 'l'
        mov byte [rsp+3], 'l'
        mov byte [rsp+4], 'o'
        mov byte [rsp+5], ' '
        mov byte [rsp+6], 'W'
        ...               ; build on stack runtime
        lea rcx, [rsp]    ; pointer to constructed string
        call printf
        add rsp, 12       ; cleanup

Advanced techniques:
    - XOR encryption with single key
    - XOR with rolling key (key changes each byte)
    - Custom encoding schemes
    - Interleaved construction (mix with junk instructions)
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass
from typing import Any

import r2morph.core.randomness as random
from r2morph.mutations.base import MutationPass
from r2morph.mutations.stack_strings_helpers import (
    EncodingScheme,
    StackStringOptions,
    _add_shift_decode_loop_x64,
    _format_plain_stack_byte,
    _xor_rolling_decode_loop_x64,
    _xor_single_decode_loop_x64,
    add_shift_encode,
    find_printable_strings,
    generate_aes_decode_asm_x64,
    generate_aes_decode_asm_x86,
    generate_stack_string_x64,
    generate_stack_string_x86,
    xor_bytes,
    xor_rolling,
)
from r2morph.relocations.cave_injector import CodeCaveInjector

logger = logging.getLogger(__name__)

_RELATIVE_JUMP_SIZE = 5
_MAX_STRINGS_PER_BINARY = 32
_X86_64_BITS = 64
_SIGNED_32_MIN = -(1 << 31)
_SIGNED_32_MAX = (1 << 31) - 1
_ASCII_SPACE = 0x20
_PRINTABLE_ASCII_MAX = 0x7E
_BYTE_MASK = 0xFF
_ROLLING_KEY_INCREMENT = 1
_ROLLING_KEY_MULTIPLIER = 7
_X86_64_ARCHITECTURES = frozenset({"x86_64", "x86-64", "x64", "amd64"})
_X86_64_POINTER_REGISTERS = {
    "eax": "rax",
    "ebx": "rbx",
    "ecx": "rcx",
    "edx": "rdx",
    "edi": "rdi",
    "esi": "rsi",
    "ebp": "rbp",
    "esp": "rsp",
}
_SUPPORTED_APPLY_ENCODINGS = frozenset(
    {
        EncodingScheme.PLAIN,
        EncodingScheme.XOR_SINGLE,
        EncodingScheme.XOR_ROLLING,
        EncodingScheme.ADD_SHIFT,
    }
)


@dataclass(frozen=True)
class _StringReference:
    """A conservatively supported string construction followed by a call."""

    function_address: int
    reference_address: int
    reference_text: str
    register: str
    call_target: int
    continuation: int
    span: int


@dataclass(frozen=True)
class _StackBuild:
    """Encoded bytes and deterministic choices shared by provisional and final assembly."""

    original_data: bytes
    encoded_data: bytes
    key: int
    shift: int
    junk_offsets: tuple[int, ...]


@dataclass(frozen=True)
class _PreparedRewrite:
    """Validated stack-string rewrite before cave allocation."""

    string_address: int
    original_string: bytes
    reference: _StringReference
    build: _StackBuild
    provisional: bytes


@dataclass(frozen=True)
class _InstalledPayload:
    """Bytes needed to commit or roll back an allocated cave rewrite."""

    actual: bytes
    original_cave: bytes
    original_site: bytes
    patched_site: bytes


def _instruction_address(instruction: dict[str, Any]) -> int | None:
    address = instruction.get("addr", instruction.get("offset"))
    return address if isinstance(address, int) else None


def _instruction_text(instruction: dict[str, Any]) -> str:
    return str(instruction.get("opcode", instruction.get("disasm", ""))).strip().lower()


def _parse_rip_relative_lea(instruction: dict[str, Any]) -> tuple[str, str] | None:
    text = _instruction_text(instruction)
    match = re.fullmatch(r"lea\s+([a-z][a-z0-9]+)\s*,\s*\[\s*rip(?:\s*[+-].*)?\]", text)
    if match is None:
        return None
    return match.group(1), text


def _parse_string_argument(instruction: dict[str, Any]) -> tuple[str, str] | None:
    """Parse a direct string-pointer argument emitted by common x86-64 compilers."""
    parsed = _parse_rip_relative_lea(instruction)
    if parsed is not None:
        return parsed

    text = _instruction_text(instruction)
    match = re.fullmatch(r"mov\s+([a-z][a-z0-9]+)\s*,\s*(.+)", text)
    if match is None:
        return None
    operand = match.group(2).strip()
    if operand.startswith(("[", "qword [", "dword [")):
        return None
    register = _X86_64_POINTER_REGISTERS.get(match.group(1), match.group(1))
    return register, text


def _direct_call_target(instruction: dict[str, Any]) -> int | None:
    if instruction.get("type") not in {"call", "rcall", "jmp"}:
        return None
    target = instruction.get("jump")
    return target if isinstance(target, int) else None


def _find_function_instructions(binary: Any, function_address: int) -> list[dict[str, Any]]:
    return [
        instruction
        for instruction in binary.get_function_disasm(function_address)
        if _instruction_address(instruction) is not None
    ]


def _find_string_reference(binary: Any, string_address: int) -> _StringReference | None:
    references = binary.get_xrefs_to(string_address)
    if len(references) != 1:
        return None
    reference = references[0]
    reference_address = reference.get("from")
    function_address = reference.get("fcn_addr")
    if not isinstance(reference_address, int):
        return None
    function_addresses = (
        [function_address]
        if isinstance(function_address, int)
        else [int(function.get("addr")) for function in binary.get_functions() if isinstance(function.get("addr"), int)]
    )
    for candidate_address in function_addresses:
        instructions = _find_function_instructions(binary, candidate_address)
        for index, instruction in enumerate(instructions[:-1]):
            if _instruction_address(instruction) != reference_address:
                continue
            parsed = _parse_string_argument(instruction)
            call = instructions[index + 1]
            call_target = _direct_call_target(call)
            call_address = _instruction_address(call)
            call_size = call.get("size")
            if (
                parsed is None
                or call_target is None
                or not isinstance(call_address, int)
                or not isinstance(call_size, int)
            ):
                return None
            return _StringReference(
                candidate_address,
                reference_address,
                parsed[1],
                parsed[0],
                call_target,
                call_address + call_size,
                call_address + call_size - reference_address,
            )
    return None


def _encoded_data(data: bytes, encoding: str, key: int, shift: int) -> bytes | None:
    if encoding == EncodingScheme.PLAIN:
        return data
    if encoding == EncodingScheme.XOR_SINGLE:
        return xor_bytes(data, key)
    if encoding == EncodingScheme.XOR_ROLLING:
        return xor_rolling(data, key)[0]
    if encoding == EncodingScheme.ADD_SHIFT:
        return add_shift_encode(data, shift)
    return None


def _stack_allocation_size(data_length: int) -> int:
    return ((data_length + 15) // 16) * 16


def _relative_jump(from_address: int, to_address: int) -> bytes | None:
    offset = to_address - (from_address + _RELATIVE_JUMP_SIZE)
    if not _SIGNED_32_MIN <= offset <= _SIGNED_32_MAX:
        return None
    return b"\xe9" + struct.pack("<i", offset)


class StackStringsPass(MutationPass):
    """
    Mutation pass that transforms static strings into stack-built strings.

    Finds string literals in the binary and replaces them with
    dynamically constructed strings on the stack, making them harder
    to detect statically.

    Config options:
        - probability: Probability of transforming each string (default: 0.5)
        - min_length: Minimum string length to transform (default: 4)
        - max_length: Maximum string length to transform (default: 256)
        - encoding: Encoding scheme ("plain", "xor_single", "xor_rolling", "add_shift")
        - interleave_junk: Add junk instructions between movs (default: True)
        - junk_probability: Probability of junk instruction per mov (default: 0.2)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="StackStrings", config=config)
        self.probability = self.config.get("probability", 0.5)
        self.min_length = self.config.get("min_length", 4)
        self.max_length = self.config.get("max_length", 256)
        self.encoding = self.config.get("encoding", EncodingScheme.XOR_SINGLE)
        self.interleave_junk = self.config.get("interleave_junk", True)
        self.junk_probability = self.config.get("junk_probability", 0.2)
        self.set_support(
            formats=("ELF",),
            architectures=("x86_64",),
            validators=("structural",),
            stability="experimental",
            notes=(
                "rewrites unique RIP-relative call arguments on ELF x86-64",
                "supports plain and bytewise encoded stack construction",
                "rejects unsupported references without changing bytes",
            ),
        )

    def _find_strings_in_section(self, binary: Any, section: dict[str, Any]) -> list[dict[str, Any]]:
        """Find strings in a binary section."""
        strings: list[dict[str, Any]] = []
        addr = section.get("vaddr", section.get("addr", 0))
        size = section.get("size", 0)

        if size == 0 or not section.get("name", "").startswith("."):
            return strings

        try:
            data = binary.read_bytes(addr, size)
            found = find_printable_strings(data, self.min_length)

            for offset, raw_string_data in found:
                first_printable = next(
                    (
                        index
                        for index, byte in enumerate(raw_string_data)
                        if _ASCII_SPACE <= byte <= _PRINTABLE_ASCII_MAX
                    ),
                    None,
                )
                if first_printable is None:
                    continue
                string_data = raw_string_data[first_printable:].rstrip(b"\x00")
                if len(string_data) > self.max_length:
                    continue
                if len(string_data) < self.min_length:
                    continue

                strings.append(
                    {
                        "address": addr + offset + first_printable,
                        "size": len(string_data),
                        "data": string_data,
                        "section": section.get("name", "unknown"),
                        "preview": string_data[:50].decode("utf-8", errors="replace"),
                    }
                )
        except Exception as e:
            logger.debug(f"Failed to read section {section.get('name')}: {e}")

        return strings

    def _generate_stack_string_asm(self, string_data: bytes, arch: str = "x64") -> tuple[str, list[str]]:
        """Generate assembly for stack string construction."""
        xor_key = random.randint(0x10, 0xEF)
        add_shift = random.randint(1, 50)

        generator = generate_stack_string_x64 if arch == "x64" else generate_stack_string_x86

        return generator(
            string_data,
            StackStringOptions(
                encoding=self.encoding,
                xor_key=xor_key,
                add_shift=add_shift,
                interleave_junk=self.interleave_junk,
                junk_probability=self.junk_probability,
            ),
        )

    @staticmethod
    def _supports_apply_target(binary: Any) -> bool:
        arch_info = binary.get_arch_info()
        binary_format = str(arch_info.get("format", "")).lower()
        architecture = str(arch_info.get("arch", "")).lower()
        bits = arch_info.get("bits")
        x86_64 = architecture in _X86_64_ARCHITECTURES or (architecture == "x86" and bits == _X86_64_BITS)
        return binary_format.startswith("elf") and x86_64

    @staticmethod
    def _has_safe_stack_layout(binary: Any, reference: _StringReference) -> bool:
        """Reject callers whose stack layout cannot be preserved around the call."""
        for instruction in _find_function_instructions(binary, reference.function_address):
            address = _instruction_address(instruction)
            if address is None or address >= reference.reference_address:
                break
            text = _instruction_text(instruction)
            mnemonic = text.split(maxsplit=1)[0] if text else ""
            if mnemonic in {"push", "pop", "leave"} or "[rsp" in text:
                return False
        return True

    def _stack_stub_instructions(
        self,
        build: _StackBuild,
        reference: _StringReference,
    ) -> list[str]:
        string_data = build.original_data
        encoded_data = build.encoded_data
        allocation = _stack_allocation_size(len(string_data))
        instructions = [f"sub rsp, {allocation}"]
        for index, byte in enumerate(encoded_data):
            instructions.append(f"mov byte [rsp+{index}], 0x{byte:02x}")
            if index in build.junk_offsets:
                instructions.append("nop")
        if self.encoding == EncodingScheme.XOR_SINGLE:
            instructions.extend(f"xor byte [rsp+{index}], 0x{build.key:02x}" for index in range(len(encoded_data)))
        elif self.encoding == EncodingScheme.XOR_ROLLING:
            rolling_key = build.key
            for index in range(len(encoded_data)):
                instructions.append(f"xor byte [rsp+{index}], 0x{rolling_key:02x}")
                if index + 1 < len(encoded_data):
                    rolling_key = (rolling_key * _ROLLING_KEY_MULTIPLIER + _ROLLING_KEY_INCREMENT) & _BYTE_MASK
        elif self.encoding == EncodingScheme.ADD_SHIFT:
            instructions.extend(f"sub byte [rsp+{index}], {build.shift}" for index in range(len(encoded_data)))
        instructions.extend(
            (
                f"lea {reference.register}, [rsp]",
                f"call 0x{reference.call_target:x}",
                f"add rsp, {_stack_allocation_size(len(build.original_data))}",
                f"jmp 0x{reference.continuation:x}",
            )
        )
        return instructions

    @staticmethod
    def _assemble_instructions(binary: Any, instructions: list[str], start_address: int) -> bytes | None:
        assembled = bytearray()
        address = start_address
        for instruction in instructions:
            try:
                encoded = binary.assemble(instruction, function_addr=address)
            except (OSError, RuntimeError, TypeError, ValueError):
                return None
            if not encoded:
                return None
            assembled.extend(encoded)
            address += len(encoded)
        return bytes(assembled)

    def _prepare_rewrite(self, binary: Any, string_info: dict[str, Any]) -> _PreparedRewrite | None:
        string_address = string_info["address"]
        string_size = string_info["size"]
        original_string = binary.read_bytes(string_address, string_size + 1)
        reference = _find_string_reference(binary, string_address)
        prepared: _PreparedRewrite | None = None
        if (
            original_string == string_info["data"] + b"\x00"
            and reference is not None
            and reference.span >= _RELATIVE_JUMP_SIZE
            and self._has_safe_stack_layout(binary, reference)
            and self.encoding in _SUPPORTED_APPLY_ENCODINGS
        ):
            key = random.randint(0x10, 0xEF)
            shift = random.randint(1, 50)
            encoded_data = _encoded_data(original_string, self.encoding, key, shift)
            if encoded_data is not None:
                junk_offsets = tuple(
                    index
                    for index in range(len(encoded_data))
                    if self.interleave_junk and random.random() < self.junk_probability
                )
                build = _StackBuild(original_string, encoded_data, key, shift, junk_offsets)
                instructions = self._stack_stub_instructions(build, reference)
                provisional = self._assemble_instructions(binary, instructions, reference.reference_address)
                if provisional is not None:
                    prepared = _PreparedRewrite(string_address, original_string, reference, build, provisional)
        return prepared

    @staticmethod
    def _restore_writes(binary: Any, writes: tuple[tuple[int, bytes], ...]) -> None:
        for address, data in writes:
            binary.write_bytes(address, data)

    def _install_payload(self, binary: Any, prepared: _PreparedRewrite, allocation: Any) -> _InstalledPayload | None:
        instructions = self._stack_stub_instructions(prepared.build, prepared.reference)
        actual = self._assemble_instructions(binary, instructions, allocation.address)
        if actual is None or len(actual) > allocation.size:
            return None
        original_cave = binary.read_bytes(allocation.address, allocation.size)
        original_site = binary.read_bytes(prepared.reference.reference_address, prepared.reference.span)
        trampoline = _relative_jump(prepared.reference.reference_address, allocation.address)
        if len(original_cave) != allocation.size or len(original_site) != prepared.reference.span or trampoline is None:
            return None
        return _InstalledPayload(
            actual.ljust(allocation.size, b"\x90"),
            original_cave,
            original_site,
            trampoline.ljust(prepared.reference.span, b"\x90"),
        )

    def _install_rewrite(self, binary: Any, prepared: _PreparedRewrite) -> bool:
        reference = prepared.reference
        injector = CodeCaveInjector(binary, min_cave_size=len(prepared.provisional))
        cave = injector.find_cave_for_code(len(prepared.provisional), require_executable=True)
        if cave is None:
            return False
        allocation = injector.allocate_from_cave(cave, len(prepared.provisional), alignment=1)
        payload = self._install_payload(binary, prepared, allocation)
        if payload is None:
            return False

        if not binary.write_bytes(allocation.address, payload.actual):
            return False
        if not binary.write_bytes(prepared.string_address, prepared.build.encoded_data):
            self._restore_writes(binary, ((allocation.address, payload.original_cave),))
            return False
        if not binary.write_bytes(reference.reference_address, payload.patched_site):
            self._restore_writes(
                binary,
                (
                    (prepared.string_address, prepared.original_string),
                    (allocation.address, payload.original_cave),
                ),
            )
            return False

        self._record_mutation(
            function_address=reference.function_address,
            start_address=reference.reference_address,
            end_address=reference.reference_address + reference.span - 1,
            original_bytes=payload.original_site,
            mutated_bytes=payload.patched_site,
            original_disasm=reference.reference_text,
            mutated_disasm=f"jmp 0x{allocation.address:x} ; stack string call bridge",
            mutation_kind="stack_strings",
            metadata={
                "string_address": prepared.string_address,
                "string_size": len(prepared.original_string),
                "cave_address": allocation.address,
                "cave_size": allocation.size,
                "encoding": self.encoding,
                "junk_instruction_count": len(prepared.build.junk_offsets),
            },
        )
        return True

    def _rewrite_string(self, binary: Any, string_info: dict[str, Any]) -> bool:
        try:
            prepared = self._prepare_rewrite(binary, string_info)
            return prepared is not None and self._install_rewrite(binary, prepared)
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            logger.debug("Skipping stack string at 0x%x: %s", string_info["address"], error)
            return False

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply stack string transformation.

        Args:
            binary: Any to transform

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying stack strings transformation")

        if not self._supports_apply_target(binary):
            return {
                "strings_found": 0,
                "strings_transformed": 0,
                "strings_previewed": 0,
                "strings_skipped": 0,
                "encoding_used": self.encoding,
                "junk_interleaved": self.interleave_junk,
                "transformation_status": "unsupported-target",
                "transformation_reason": "runtime rewriting is supported only for ELF x86-64",
            }

        self._ensure_analyzed(binary)

        all_strings = []
        transformed_count = 0
        skipped_count = 0

        try:
            sections = binary.r2.cmdj("iSj") or []
        except Exception as e:
            logger.warning(f"Failed to get sections: {e}")
            sections = []

        for section in sections:
            if not section.get("name", "").startswith("."):
                continue

            strings = self._find_strings_in_section(binary, section)
            all_strings.extend(strings)

        logger.info(f"Found {len(all_strings)} strings")

        for string_info in all_strings[: self.config.get("max_strings", _MAX_STRINGS_PER_BINARY)]:
            if random.random() > self.probability:
                skipped_count += 1
                continue

            string_data = string_info.get("data", b"")
            if not string_data:
                skipped_count += 1
                continue

            if self._rewrite_string(binary, string_info):
                transformed_count += 1
                logger.debug("Rewrote stack string at 0x%x", string_info["address"])
            else:
                skipped_count += 1

        return {
            "strings_found": len(all_strings),
            "strings_transformed": transformed_count,
            "strings_previewed": 0,
            "strings_skipped": skipped_count,
            "encoding_used": self.encoding,
            "junk_interleaved": self.interleave_junk,
            "transformation_status": "applied" if transformed_count else "no-op",
            "transformation_reason": "unsupported references or unavailable executable caves were skipped",
        }

    def preview_string(self, string: str, arch: str = "x64") -> str:
        """
        Preview what a string would look like after transformation.

        Args:
            string: String to preview
            arch: Target architecture

        Returns:
            Assembly code preview
        """
        string_data = string.encode("utf-8") + b"\x00"
        asm, _ = self._generate_stack_string_asm(string_data, arch)
        return asm


__all__ = [
    "EncodingScheme",
    "StackStringOptions",
    "StackStringsPass",
    "_add_shift_decode_loop_x64",
    "_format_plain_stack_byte",
    "_xor_rolling_decode_loop_x64",
    "_xor_single_decode_loop_x64",
    "add_shift_encode",
    "find_printable_strings",
    "generate_aes_decode_asm_x64",
    "generate_aes_decode_asm_x86",
    "generate_stack_string_x64",
    "generate_stack_string_x86",
    "xor_bytes",
    "xor_rolling",
]
