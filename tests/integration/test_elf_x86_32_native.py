"""Native differential coverage for the ELF x86 32-bit target."""

from __future__ import annotations

import platform
import shutil
import struct
from pathlib import Path

import pytest
import unicorn
from unicorn import x86_const

from r2morph.core.binary import Binary
from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.mutations.string_obfuscation import StringObfuscationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

_ELF_PT_LOAD = 1
_ELF_PAGE_SIZE = 0x1000
_ELF32_ENTRY_OFFSET = 0x18
_ELF32_PROGRAM_HEADER_OFFSET_OFFSET = 0x1C
_ELF32_PROGRAM_HEADER_SIZE_OFFSET = 0x2A
_ELF32_PROGRAM_HEADER_COUNT_OFFSET = 0x2C
_ELF32_STACK_BASE = 0x70000000
_ELF32_STACK_SIZE = 0x10000
_ELF32_SYSCALL_INTERRUPT = 0x80
_ELF32_EXIT_SYSCALL = 1
_ELF32_INSTRUCTION_LIMIT = 10_000


def _build_x86_32_elf(tmp_path: Path, complex_fixture: bool = False) -> Path:
    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("clang or gcc is required for the ELF x86 32-bit differential fixture")
    target_flags = ["-target", "i386-linux-gnu"] if Path(compiler).name == "clang" else ["-m32"]
    source = tmp_path / "x86_32_exit.S"
    basic_source = (
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    call compute\n"
        "    movl %eax, %ebx\n"
        "    movl $0, %ecx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".type compute,@function\n"
        "compute:\n"
        "    movl $40, %ecx\n"
        "    movl %ecx, %ecx\n"
        "    addl $2, %ecx\n"
        "    movl %ecx, %eax\n"
        "    ret\n"
        ".size _start, .-_start\n"
    )
    complex_source = (
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    call compute\n"
        "    movl %eax, %ebx\n"
        "    movl $0, %ecx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".type compute,@function\n"
        "compute:\n"
        "    movl $40, %ecx\n"
        "    movl %ecx, %ecx\n"
        "    movl $2, %esi\n"
        "    cmpl $0, %ecx\n"
        "    je zero\n"
        "    addl %esi, %ecx\n"
        "    jmp done\n"
        "zero:\n"
        "    addl %esi, %ecx\n"
        "done:\n"
        "    cmpl $42, %ecx\n"
        "    je validated\n"
        "    jmp finish\n"
        "validated:\n"
        "    addl $0, %ecx\n"
        "finish:\n"
        "    movl %ecx, %eax\n"
        "    ret\n"
        ".size _start, .-_start\n"
    )
    source.write_text(complex_source if complex_fixture else basic_source, encoding="ascii")
    binary_path = tmp_path / "x86_32_exit"
    linker_flags = ["-fuse-ld=lld"] if platform.system() == "Darwin" else []
    run_command(
        [
            compiler,
            *target_flags,
            *linker_flags,
            "-nostdlib",
            "-static",
            "-Wl,-e,_start",
            "-x",
            "assembler",
            "-o",
            binary_path,
            source,
        ],
        check=True,
        text=True,
    )
    return binary_path


def _emulate_elf32_exit_code(binary_path: Path) -> int:
    raw = binary_path.read_bytes()
    entry = struct.unpack_from("<I", raw, _ELF32_ENTRY_OFFSET)[0]
    program_header_offset = struct.unpack_from("<I", raw, _ELF32_PROGRAM_HEADER_OFFSET_OFFSET)[0]
    program_header_size = struct.unpack_from("<H", raw, _ELF32_PROGRAM_HEADER_SIZE_OFFSET)[0]
    program_header_count = struct.unpack_from("<H", raw, _ELF32_PROGRAM_HEADER_COUNT_OFFSET)[0]
    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    mapped_pages: set[int] = set()

    for index in range(program_header_count):
        offset = program_header_offset + index * program_header_size
        header = struct.unpack_from("<IIIIIIII", raw, offset)
        segment_type, file_offset, address, _, file_size, memory_size, _, _ = header
        if segment_type != _ELF_PT_LOAD:
            continue
        start = address & ~(_ELF_PAGE_SIZE - 1)
        end = (address + max(file_size, memory_size) + _ELF_PAGE_SIZE - 1) & ~(_ELF_PAGE_SIZE - 1)
        for page in range(start, end, _ELF_PAGE_SIZE):
            if page not in mapped_pages:
                machine.mem_map(page, _ELF_PAGE_SIZE)
                mapped_pages.add(page)
        machine.mem_write(address, raw[file_offset : file_offset + file_size])

    machine.mem_map(_ELF32_STACK_BASE, _ELF32_STACK_SIZE)
    machine.reg_write(x86_const.UC_X86_REG_ESP, _ELF32_STACK_BASE + _ELF32_STACK_SIZE // 2)
    exit_codes: list[int] = []

    def capture_exit(emulator: unicorn.Uc, interrupt: int, _user_data: object) -> None:
        if interrupt != _ELF32_SYSCALL_INTERRUPT or emulator.reg_read(x86_const.UC_X86_REG_EAX) != _ELF32_EXIT_SYSCALL:
            raise RuntimeError(f"unexpected ELF32 interrupt {interrupt}")
        exit_codes.append(emulator.reg_read(x86_const.UC_X86_REG_EBX) & 0xFF)
        emulator.emu_stop()

    machine.hook_add(unicorn.UC_HOOK_INTR, capture_exit)
    machine.emu_start(entry, 0, count=_ELF32_INSTRUCTION_LIMIT)
    if not exit_codes:
        raise RuntimeError("ELF32 execution did not reach sys_exit")
    return exit_codes[0]


def test_elf_x86_32_block_reordering_preserves_emulated_exit_code(tmp_path: Path) -> None:
    if platform.system() == "Darwin" and shutil.which("ld.lld") is None:
        pytest.skip("ld.lld is required to link an ELF32 fixture on macOS")

    binary_path = _build_x86_32_elf(tmp_path, complex_fixture=True)
    original_exit_code = _emulate_elf32_exit_code(binary_path)
    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = BlockReorderingPass({"probability": 1.0, "seed": 1, "max_functions": 10}).apply(binary)

    mutated_exit_code = _emulate_elf32_exit_code(binary_path)
    expect(result["mutations_applied"] > 0, f"ELF x86-32 block reordering made no change: {result!r}")
    expect(
        (original_exit_code, mutated_exit_code) == (42, 42),
        f"ELF x86-32 block reordering changed emulated execution: {original_exit_code} -> {mutated_exit_code}",
    )


def _build_x86_32_expansion_elf(tmp_path: Path) -> Path:
    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("clang or gcc is required for the ELF x86 32-bit expansion fixture")
    target_flags = ["-target", "i386-linux-gnu"] if Path(compiler).name == "clang" else ["-m32"]
    source = tmp_path / "x86_32_expansion.S"
    source.write_text(
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    call compute\n"
        "    movl %eax, %ebx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".type compute,@function\n"
        "compute:\n"
        "    movl $20, %ecx\n"
        "    movl %ecx, %edx\n"
        "    xorl %edx, %edx\n"
        "    movl %ecx, %edx\n"
        "    shll $1, %ecx\n"
        "    addl $2, %ecx\n"
        "    movl %ecx, %eax\n"
        "    nop\n"
        "    ret\n"
        ".size compute, .-compute\n",
        encoding="ascii",
    )
    binary_path = tmp_path / "x86_32_expansion"
    run_command(
        [
            compiler,
            *target_flags,
            "-nostdlib",
            "-static",
            "-Wl,-e,_start",
            "-x",
            "assembler",
            "-o",
            binary_path,
            source,
        ],
        check=True,
        text=True,
    )
    return binary_path


def test_elf_x86_32_instruction_substitution_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        mutation_pass = InstructionSubstitutionPass(
            config={"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        )
        result = mutation_pass.apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit instruction substitution changed native execution",
    )


def test_elf_x86_32_nop_insertion_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 1337}).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit NOP insertion changed native execution",
    )


def test_elf_x86_32_register_substitution_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = RegisterSubstitutionPass(
            config={"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        ).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit register substitution changed native execution",
    )


def test_elf_x86_32_complex_pass_sequence_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_elf(tmp_path, complex_fixture=True)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        results = (
            RegisterSubstitutionPass(
                config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 20260919}
            ).apply(binary),
            NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 20260919}).apply(binary),
            InstructionSubstitutionPass(
                config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 20260919}
            ).apply(binary),
        )

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        all(result["mutations_applied"] > 0 for result in results)
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "complex ELF x86 32-bit mutation sequence changed native execution: "
        f"original={original.returncode, original.stdout, original.stderr!r}; "
        f"mutated={mutated.returncode, mutated.stdout, mutated.stderr!r}; "
        f"results={results!r}",
    )


def test_elf_x86_32_constant_unfolding_zero_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("clang or gcc is required for the ELF x86 32-bit differential fixture")
    target_flags = ["-target", "i386-linux-gnu"] if Path(compiler).name == "clang" else ["-m32"]
    source = tmp_path / "x86_32_constant.S"
    binary_path = tmp_path / "x86_32_constant"
    source.write_text(
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    call compute\n"
        "    movl %eax, %ebx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".type compute,@function\n"
        "compute:\n"
        "    movl $0, %ecx\n"
        "    addl $42, %ecx\n"
        "    movl %ecx, %eax\n"
        "    ret\n"
        ".size _start, .-_start\n",
        encoding="ascii",
    )
    run_command(
        [
            compiler,
            *target_flags,
            "-nostdlib",
            "-static",
            "-Wl,-e,_start",
            "-x",
            "assembler",
            "-o",
            binary_path,
            source,
        ],
        check=True,
        text=True,
    )
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = ConstantUnfoldingPass(config={"probability": 1.0, "seed": 20260919}).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        f"x86 32-bit constant unfolding changed native execution: {result=}",
    )


def test_elf_x86_32_instruction_expansion_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_expansion_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = InstructionExpansionPass(
            config={"max_expansions_per_function": 1, "probability": 1.0, "seed": 20260923}
        ).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit instruction expansion changed native execution",
    )


def test_elf_x86_32_string_obfuscation_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("clang or gcc is required for the ELF x86 32-bit differential fixture")
    target_flags = ["-target", "i386-linux-gnu"] if Path(compiler).name == "clang" else ["-m32"]
    source = tmp_path / "x86_32_string.S"
    source.write_text(
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    movl $42, %ebx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".size _start, .-_start\n"
        ".section .rodata\n"
        ".type unreferenced_evidence_string,@object\n"
        "unreferenced_evidence_string:\n"
        '    .asciz "platform-string-evidence"\n',
        encoding="ascii",
    )
    binary_path = tmp_path / "x86_32_string"
    run_command(
        [
            compiler,
            *target_flags,
            "-nostdlib",
            "-static",
            "-Wl,-e,_start",
            "-x",
            "assembler",
            "-o",
            binary_path,
            source,
        ],
        check=True,
        text=True,
    )
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = StringObfuscationPass({"probability": 1.0, "encoding": "xor", "max_strings_per_section": 1}).apply(
            binary
        )

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit string obfuscation changed native execution",
    )
