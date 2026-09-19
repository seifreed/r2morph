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
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r2morph.adapters.process import run_process
from r2morph.core.binary import Binary
from r2morph.mutations import (
    BlockReorderingPass,
    ConstantUnfoldingPass,
    ControlFlowFlatteningPass,
    DataFlowMutationPass,
    DeadCodeInjectionPass,
    InstructionExpansionPass,
    InstructionSubstitutionPass,
    NopInsertionPass,
    RegisterSubstitutionPass,
)
from r2morph.mutations.anti_disassembly import AntiDisassemblyPass
from r2morph.mutations.api_hashing import APIHashingPass
from r2morph.mutations.base import MutationPass
from r2morph.mutations.code_mobility import CodeMobilityPass
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.function_outlining import FunctionOutliningPass
from r2morph.mutations.import_obfuscation import ImportTableObfuscationPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from r2morph.mutations.pattern_substitution import PatternSubstitutionPass
from r2morph.mutations.polymorphic_engine import PolymorphicEnginePass
from r2morph.mutations.self_modifying_code import SelfModifyingCodePass
from r2morph.mutations.short_jump_patching import ShortJumpPatchingPass
from r2morph.mutations.stack_strings import StackStringsPass
from r2morph.mutations.string_obfuscation import StringObfuscationPass
from tests.integration.elf_emulator import emulate_exit_code

_ELF_MAGIC = b"\x7fELF"
_ET_EXEC = 2
_ET_DYN = 3
_EM_X86_64 = 62
_ELFCLASS64 = 2
_BITS_64 = 64
_ELF_IDENT_HEADER_BYTES = 20
_PIE_LOAD_BIAS = 0x5555_5555_4000
_RUNTIME_TIMEOUT_SECONDS = 5.0
_PREVIEW_BYTES = 32
_MAX_AFFECTED_INSTRUCTION_MNEMONICS = 256
_FULL_COVERAGE_PERCENT = 100.0
_COMPLETE_RUN_FIELD = 0
_MISSING_RUN_FIELD = 1
_DIFFERENTIAL_PLATFORM_SCOPE = {"os": "linux", "format": "ELF", "architecture": "x86-64"}
_DIFFERENTIAL_PLATFORM_GAP_SCOPE = {
    "formats": ["Mach-O", "PE"],
    "architectures": ["AArch64", "ARM", "x86"],
}
_DIFFERENTIAL_CORPUS_GAP_SCOPE = {
    "corpus_families": ["additional-corpus-families"],
    "input_sources": ["generated-inputs"],
}
_DEFAULT_RUNTIME_INPUTS: tuple[tuple[str, ...], ...] = ((),)
_GENERATED_RUNTIME_INPUTS: tuple[tuple[str, ...], ...] = (
    (),
    ("0",),
    ("1",),
    ("-1",),
    ("4294967295",),
    ("alpha",),
    ("alpha", "7"),
    ("--", "ffff"),
    ("path/with/slash", "spaced value"),
)
_DEFAULT_INPUT_SOURCE = "default-argv"
_GENERATED_INPUT_SOURCE = "generated-argv"
_GENERATED_CORPUS_FAMILY = "generated-elf-x86-64"
_GENERATED_CPP_CORPUS_FAMILY = "generated-cpp-x86-64"
_GENERATED_CORPUS_PROFILES = (
    ("gcc-o0", "gcc", "-O0", "-fno-pie", "-no-pie"),
    ("gcc-o1", "gcc", "-O1", "-fno-pie", "-no-pie"),
    ("gcc-o2", "gcc", "-O2", "-fno-pie", "-no-pie"),
    ("gcc-o3", "gcc", "-O3", "-fno-pie", "-no-pie"),
    ("gcc-os", "gcc", "-Os", "-fno-pie", "-no-pie"),
    ("gcc-pie-o2", "gcc", "-O2", "-fPIE", "-pie"),
    ("gcc-static-o2", "gcc", "-O2", "-fno-pie", "-no-pie", "-static"),
    ("gcc-stripped-o2", "gcc", "-O2", "-fno-pie", "-no-pie", "-s"),
    ("clang-o0", "clang", "-O0", "-fno-pie", "-no-pie"),
    ("clang-o2", "clang", "-O2", "-fno-pie", "-no-pie"),
    ("clang-o3", "clang", "-O3", "-fno-pie", "-no-pie"),
    ("clang-pie-o2", "clang", "-O2", "-fPIE", "-pie"),
)
_GENERATED_CPP_CORPUS_PROFILES = (
    ("gxx-o0", "g++", "-O0", "-fno-pie", "-no-pie"),
    ("gxx-o2", "g++", "-O2", "-fno-pie", "-no-pie"),
    ("clangxx-o0", "clang++", "-O0", "-fno-pie", "-no-pie"),
    ("clangxx-o2", "clang++", "-O2", "-fno-pie", "-no-pie"),
)
_GENERATED_UNREACHABLE_PADDING = r"""
__asm__(
    ".section .text.r2morph_padding,\"ax\",@progbits\n"
    ".balign 16\n"
    ".rept 512\n"
    "nop\n"
    ".endr\n"
    ".previous\n"
);
"""
_GENERATED_CORPUS_SOURCES = {
    "generated_calls": r"""
#include <stdint.h>

typedef int (*call_target)(int);

__attribute__((noinline)) static int direct_target(int value) {
    return value * 5 + 3;
}

__attribute__((noinline)) static int indirect_target(int value) {
    return (value ^ 0x2a) - 7;
}

static call_target volatile selected_target = indirect_target;

__attribute__((noinline)) static int call_mix(int value) {
    int direct = direct_target(value + 7);
    int indirect = selected_target(direct);
    return (direct + indirect) & 127;
}

int main(int argc, char **argv) {
    (void)argv;
    return call_mix(argc);
}
""",
    "generated_branch": r"""
#include <stdint.h>
#include <stdlib.h>

__attribute__((noinline)) static int call_probe(int value) {
    void *buffer = malloc((size_t)(value & 15) + 1);
    free(buffer);
    return value + 1;
}

__asm__(
    ".text\n"
    ".globl short_jump_probe\n"
    ".type short_jump_probe,@function\n"
    "short_jump_probe:\n"
    "mov %edi, %ecx\n"
    "jrcxz 1f\n"
    ".rept 8\n"
    "nop\n"
    ".endr\n"
    "mov $1, %eax\n"
    ".rept 3\n"
    "nop\n"
    ".endr\n"
    "ret\n"
    "1:\n"
    "xor %eax, %eax\n"
    "ret\n"
    ".size short_jump_probe, .-short_jump_probe\n"
);

__asm__(
    ".text\n"
    ".globl self_modify_probe\n"
    ".type self_modify_probe,@function\n"
    "self_modify_probe:\n"
    "mov %edi, %eax\n"
    "add $1, %eax\n"
    "imul $3, %eax, %eax\n"
    ".rept 8\n"
    "nop\n"
    ".endr\n"
    "ret\n"
    ".size self_modify_probe, .-self_modify_probe\n"
);

extern int short_jump_probe(int value);
extern int self_modify_probe(int value);

__attribute__((noinline)) static int fold(int argc, char **argv) {
    uint32_t acc = (uint32_t)argc;
    for (int i = 0; i < argc; ++i) {
        const unsigned char *p = (const unsigned char *)argv[i];
        while (*p) {
            acc = ((acc << 3) ^ *p) + (acc >> 1);
            ++p;
        }
    }
    acc += (uint32_t)call_probe((int)acc);
    acc += (uint32_t)short_jump_probe((int)acc);
    acc += (uint32_t)self_modify_probe((int)acc);
    switch (acc & 3) {
    case 0: return acc & 127;
    case 1: return (acc + 7) & 127;
    case 2: return (acc ^ 0x55) & 127;
    default: return (acc - 3) & 127;
    }
}

int main(int argc, char **argv) { return fold(argc, argv); }
""",
    "generated_memory": r"""
#include <stdint.h>
#include <string.h>

__attribute__((noinline)) static int mix(const uint8_t *data, int count) {
    uint32_t acc = 0x12345678u;
    for (int i = 0; i < count; ++i) {
        acc ^= (uint32_t)data[i] << ((i & 3) * 8);
        acc = (acc << 5) | (acc >> 27);
    }
    return (int)(acc & 127u);
}

int main(int argc, char **argv) {
    return argc > 1 ? mix((const uint8_t *)argv[1], (int)strlen(argv[1])) : mix((const uint8_t *)"r2morph", 7);
}
""",
    "generated_string": r"""
#include <stddef.h>
#include <stdint.h>

__attribute__((noinline)) static int copy_bytes(void) {
    uint8_t source[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t destination[8] = {0};
    __asm__ volatile(
        "mov %[source], %%rsi\n"
        "mov %[destination], %%rdi\n"
        "mov $8, %%rcx\n"
        "cld\n"
        "rep movsb\n"
        :
        : [source] "r"(source), [destination] "r"(destination)
        : "rsi", "rdi", "rcx", "memory");
    return destination[0] + destination[7];
}

int main(void) { return copy_bytes() == 9 ? 42 : 1; }
""",
    "generated_xlat": r"""
#include <stdint.h>

__attribute__((noinline)) static int table_lookup(unsigned int value) {
    static const uint8_t table[256] = {
        [0] = 3, [1] = 5, [7] = 11, [42] = 73, [255] = 127,
    };
    unsigned long index = value & 255u;
    const uint8_t *base = table;
    __asm__ volatile("xlatb" : "+a"(index) : "b"(base) : "memory");
    return (int)(uint8_t)index;
}

int main(void) { return table_lookup(42) == 73 ? 42 : 1; }
""",
    "generated_abi": r"""
#include <stdarg.h>
#include <stdint.h>

static _Thread_local uint64_t thread_value;

__attribute__((noinline)) static long sum_stack(
    long first, long second, long third, long fourth,
    long fifth, long sixth, long seventh, long eighth
) {
    return first + second + third + fourth + fifth + sixth + seventh + eighth;
}

__attribute__((noinline)) static long sum_varargs(int count, ...) {
    va_list values;
    va_start(values, count);
    long total = 0;
    for (int index = 0; index < count; ++index) {
        total += va_arg(values, long);
    }
    va_end(values);
    return total;
}

int main(int argc, char **argv) {
    (void)argv;
    thread_value = (uint64_t)argc + 5u;
    long total = sum_stack(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L);
    total += sum_varargs(5, 1L, 2L, 3L, 4L, 5L);
    return (int)((total + (long)thread_value) & 127L);
}
""",
    "generated_lookup": r"""
#include <stdint.h>

static const uint8_t table[16] = {
    0x31, 0x7c, 0x02, 0x55, 0x91, 0x0f, 0xa4, 0x18,
    0xc3, 0x6d, 0x22, 0xb8, 0x49, 0x03, 0xee, 0x10
};

__attribute__((noinline)) static int lookup_mix(int argc) {
    uint32_t acc = 0x6d2b79f5u ^ (uint32_t)argc;
    for (int i = 0; i < 32; ++i) {
        uint8_t value = table[(acc + (uint32_t)i) & 15u];
        acc ^= (uint32_t)value << ((i & 3) * 8);
        acc = (acc >> 7) | (acc << 25);
    }
    return (int)(acc & 127u);
}

    int main(int argc, char **argv) {
        (void)argv;
        return lookup_mix(argc);
    }
""",
    "generated_extended": r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char extended_anchor[] = "r2morph extended maturity corpus anchor";
__attribute__((used, section(".rodata"))) static const char unreferenced_anchor[] =
    "generic unreferenced maturity string anchor";

__attribute__((noinline)) static int opaque_probe(int value) {
    volatile int state = value;
    if ((state & 1) != 0) {
        state += 3;
        state ^= 0x55;
        state += 7;
    } else {
        state -= 2;
        state ^= 0xaa;
        state -= 5;
    }
    return state;
}

__asm__(
    ".text\n"
    ".globl data_flow_probe\n"
    ".type data_flow_probe,@function\n"
    "data_flow_probe:\n"
    "mov %rdi, %rcx\n"
    "mov %rdi, %rax\n"
    "add $3, %rax\n"
    "mov %rax, %rdx\n"
    "add $4, %rax\n"
    "ret\n"
    ".size data_flow_probe, .-data_flow_probe\n"
);

extern int data_flow_probe(int value);

__attribute__((noinline)) static int straight_line(int value) {
    uint32_t state = (uint32_t)value + 0x13579bdfu;
    state ^= 0xa5a5a5a5u;
    state = (state << 7) | (state >> 25);
    state += 0x2468ace0u;
    state ^= state >> 11;
    state = (state << 3) | (state >> 29);
    return (int)(state & 127u);
}

__attribute__((noinline)) static int branch_and_memory(const char *input, int count) {
    uint32_t state = (uint32_t)count;
    for (int index = 0; index < count; ++index) {
        state ^= (uint32_t)(unsigned char)input[index] << ((index & 3) * 8);
        state = state * 33u + (uint32_t)index;
    }
    return (int)(state & 127u);
}

int main(int argc, char **argv) {
    const char *input = argc > 1 ? argv[1] : extended_anchor;
    size_t length = strlen(input);
    char *copy = malloc(length + 1);
    if (copy == NULL) {
        return 127;
    }
    memcpy(copy, input, length + 1);
    int result = straight_line((int)length) + branch_and_memory(copy, (int)length);
    result += opaque_probe((int)length) + data_flow_probe((int)length);
    free(copy);
    return (result + (int)strlen(extended_anchor)) & 127;
}
""",
    "generated_stack_strings": r"""
#include <stddef.h>

static volatile int observed_result;

__attribute__((noinline)) static int consume_stack_string(const char *value) {
    int result = value[0] == 's' ? 0 : 1;
    observed_result = result;
    return result;
}

__attribute__((noinline)) static int build_stack_string(void) {
    const char *value = "stack-string-native";
    int result = consume_stack_string(value);
    return result + observed_result - observed_result;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return build_stack_string();
}

__asm__(
    ".section .text.r2morph_stack_cave,\"ax\",@progbits\n"
    ".balign 16\n"
    ".rept 4096\n"
    "nop\n"
    ".endr\n"
    ".previous\n"
);
""",
    "generated_pointers": r"""
#include <stdint.h>

typedef struct {
    uint32_t left;
    uint32_t right;
} Pair;

__attribute__((noinline)) static uint32_t fold(const uint32_t *value) {
    uint32_t state = *value ^ 0x9e3779b9u;
    uint32_t *alias = &state;
    *alias = (*alias << 5) | (*alias >> 27);
    return (*alias * 33u) ^ (*value + 17u);
}

__attribute__((noinline)) static uint32_t combine(Pair *pair) {
    uint32_t *first = &pair->left;
    uint32_t *second = &pair->right;
    return fold(first) + (fold(second) ^ *first);
}

int main(int argc, char **argv) {
    (void)argv;
    Pair pair = {(uint32_t)argc + 3u, (uint32_t)argc * 7u + 11u};
    return (int)(combine(&pair) & 127u);
}
""",
    "generated_recursive": r"""
#include <stdint.h>

__attribute__((noinline)) static uint32_t gcd_recursive(uint32_t left, uint32_t right) {
    return right == 0 ? left : gcd_recursive(right, left % right);
}

__attribute__((noinline)) static uint32_t walk_recursive(uint32_t value, int depth) {
    if (depth <= 0) {
        return value ^ 0x5a5a5a5au;
    }
    return walk_recursive(value + (uint32_t)depth, depth - 1) ^ (value << (depth & 3));
}

int main(int argc, char **argv) {
    (void)argv;
    uint32_t value = (uint32_t)argc * 19u + 37u;
    uint32_t result = gcd_recursive(value + 91u, value + 47u);
    result ^= walk_recursive(value, 4);
    return (int)(result & 127u);
}
""",
    "generated_cpp": r"""
#include <cstdint>

template <typename T>
static T mix_value(T value, T salt) {
    return (value ^ salt) + static_cast<T>(value << 3);
}

class Probe {
public:
    virtual ~Probe() = default;
    virtual int run(int value) const = 0;
};

class DerivedProbe final : public Probe {
public:
    int run(int value) const override {
        const std::uint32_t mixed = mix_value<std::uint32_t>(
            static_cast<std::uint32_t>(value), 0x13579bdfu);
        return static_cast<int>((mixed ^ (mixed >> 11)) & 127u);
    }
};

static int dispatch(const Probe& probe, int value) {
    return probe.run(value) ^ 0x2d;
}

int main(int argc, char** argv) {
    (void)argv;
    const DerivedProbe probe;
    return (dispatch(probe, argc) + dispatch(probe, argc + 1)) & 127;
}
""",
}
DEFAULT_MUTATION_NAME = "CodeVirtualization"
CORPUS_PASS_NAMES = (
    "BlockReordering",
    "CodeVirtualization",
    "ConstantUnfolding",
    "ControlFlowFlattening",
    "DeadCodeInjection",
    "InstructionExpansion",
    "InstructionSubstitution",
    "NopInsertion",
    "PatternSubstitution",
    "RegisterSubstitution",
)
EXTENDED_MATURITY_PASS_NAMES = (
    "AntiDisassembly",
    "APIHashing",
    "CodeMobility",
    "DataFlowMutation",
    "FunctionOutlining",
    "ImportObfuscation",
    "OpaquePredicates",
    "PolymorphicEngine",
    "SelfModifyingCode",
    "ShortJumpPatching",
    "StackStrings",
    "StringObfuscation",
)
_PASS_TYPES: dict[str, type[MutationPass]] = {
    "AntiDisassembly": AntiDisassemblyPass,
    "APIHashing": APIHashingPass,
    "BlockReordering": BlockReorderingPass,
    "CodeMobility": CodeMobilityPass,
    "CodeVirtualization": CodeVirtualizationPass,
    "ConstantUnfolding": ConstantUnfoldingPass,
    "ControlFlowFlattening": ControlFlowFlatteningPass,
    "DataFlowMutation": DataFlowMutationPass,
    "DeadCodeInjection": DeadCodeInjectionPass,
    "FunctionOutlining": FunctionOutliningPass,
    "ImportObfuscation": ImportTableObfuscationPass,
    "InstructionExpansion": InstructionExpansionPass,
    "InstructionSubstitution": InstructionSubstitutionPass,
    "NopInsertion": NopInsertionPass,
    "OpaquePredicates": OpaquePredicatePass,
    "PatternSubstitution": PatternSubstitutionPass,
    "PolymorphicEngine": PolymorphicEnginePass,
    "RegisterSubstitution": RegisterSubstitutionPass,
    "SelfModifyingCode": SelfModifyingCodePass,
    "ShortJumpPatching": ShortJumpPatchingPass,
    "StackStrings": StackStringsPass,
    "StringObfuscation": StringObfuscationPass,
}
_PASS_LABELS = {
    "AntiDisassembly": "anti-disassembly",
    "APIHashing": "api-hashing",
    "BlockReordering": "block-reordering",
    "CodeMobility": "code-mobility",
    "CodeVirtualization": "code-virtualization",
    "ConstantUnfolding": "constant-unfolding",
    "ControlFlowFlattening": "control-flow-flattening",
    "DataFlowMutation": "data-flow-mutation",
    "DeadCodeInjection": "dead-code-injection",
    "FunctionOutlining": "function-outlining",
    "ImportObfuscation": "import-obfuscation",
    "InstructionExpansion": "instruction-expansion",
    "InstructionSubstitution": "instruction-substitution",
    "NopInsertion": "nop-insertion",
    "OpaquePredicates": "opaque-predicates",
    "PatternSubstitution": "pattern-substitution",
    "PolymorphicEngine": "polymorphic-engine",
    "RegisterSubstitution": "register-substitution",
    "SelfModifyingCode": "self-modifying-code",
    "ShortJumpPatching": "short-jump-patching",
    "StackStrings": "stack-strings",
    "StringObfuscation": "string-obfuscation",
}
_COVERAGE_PERCENT_FIELDS = {
    "runtime_observable": "runtime_observable_coverage_percent",
    "output_size": "output_size_coverage_percent",
    "transform_duration": "transform_duration_coverage_percent",
    "runtime_duration": "runtime_duration_coverage_percent",
    "static_metric": "static_metric_coverage_percent",
    "complete_evidence": "complete_evidence_coverage_percent",
}
_METRIC_RUN_FIELDS = {
    "runtime_observable": ("runtime_observable_complete_runs", "runtime_observable_missing_runs"),
    "output_size": ("output_size_complete_runs", "output_size_missing_runs"),
    "transform_duration": ("transform_duration_complete_runs", "transform_duration_missing_runs"),
    "runtime_duration": ("runtime_duration_complete_runs", "runtime_duration_missing_runs"),
    "static_metric": ("static_metric_complete_runs", "static_metric_missing_runs"),
    "complete_evidence": ("complete_evidence_runs", "complete_evidence_missing_runs"),
}
_APPLIED_COUNT_FIELDS = (
    "mutations_applied",
    "functions_virtualized",
    "mutations_applied",
    "total_injections",
    "total_patched",
    "imports_hashed",
    "blocks_moved",
    "functions_outlined",
    "functions_encrypted",
    "chunks_relocated",
    "strings_obfuscated",
)


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


def _runtime_command(
    path: Path,
    arguments: tuple[str, ...] = (),
    invocation_path: str | None = None,
) -> list[str]:
    with path.open("rb") as handle:
        first_line = handle.readline(4096)
    command_path = invocation_path or str(path)
    if not first_line.startswith(b"#!"):
        return [command_path, *arguments]
    interpreter = shlex.split(first_line[2:].decode("utf-8", errors="replace"))
    return [*interpreter, command_path, *arguments] if interpreter else [command_path, *arguments]


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


def _runtime_artifacts(path: Path, arguments: tuple[str, ...] = ()) -> dict[str, object]:
    """Run a fixture in isolation and retain bounded, reproducible observables."""
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r2morph-runtime-") as temporary:
        workdir = Path(temporary)
        runtime_path = workdir / "program"
        shutil.copyfile(path, runtime_path)
        runtime_path.chmod(0o700)
        result = asyncio.run(_run_runtime(_runtime_command(runtime_path, arguments, f"./{runtime_path.name}"), workdir))
        result["argv"] = list(arguments)
        result["duration_seconds"] = time.perf_counter() - started
        result["created_files"] = _snapshot_created_files(workdir)
        return result


def _runtime_input_artifacts(path: Path, runtime_inputs: tuple[tuple[str, ...], ...]) -> list[dict[str, object]]:
    return [_runtime_artifacts(path, arguments) for arguments in runtime_inputs]


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
    header = path.read_bytes()[:_ELF_IDENT_HEADER_BYTES]
    load_bias = (
        _PIE_LOAD_BIAS
        if len(header) >= _ELF_IDENT_HEADER_BYTES
        and header[:4] == _ELF_MAGIC
        and struct.unpack_from("<H", header, 16)[0] == _ET_DYN
        else 0
    )
    try:
        exit_code = emulate_exit_code(path, load_bias=load_bias)
    except Exception as error:  # Measurement boundary records emulator failures per artifact.
        return {
            "status": "error",
            "error_type": type(error).__name__,
            "error": str(error),
            "load_bias": load_bias,
            "duration_seconds": time.perf_counter() - started,
        }
    return {
        "status": "completed" if exit_code is not None else "no_exit_syscall",
        "exit_code": exit_code,
        "load_bias": load_bias,
        "duration_seconds": time.perf_counter() - started,
    }


def _runtime_observables_equal(expected: object, actual: object) -> bool:
    """Compare bounded native-runtime observables without retaining raw output."""
    return _runtime_observable_failure_reason(expected, actual) is None


def _runtime_input_observables_equal(expected: object, actual: object) -> bool:
    if not isinstance(expected, list) or not isinstance(actual, list) or len(expected) != len(actual):
        return False
    return all(
        _runtime_observables_equal(expected_item, actual_item)
        for expected_item, actual_item in zip(expected, actual, strict=True)
    )


def _runtime_observable_failure_reason(expected: object, actual: object) -> str | None:
    if (
        not isinstance(expected, Mapping)
        or not isinstance(actual, Mapping)
        or expected.get("status") != "completed"
        or actual.get("status") != "completed"
    ):
        return "runtime_not_completed"
    for field in ("return_code", "error_type"):
        if expected.get(field) != actual.get(field):
            return field
    for stream in ("stdout", "stderr"):
        expected_digest = expected.get(stream)
        actual_digest = actual.get(stream)
        if not isinstance(expected_digest, Mapping) or not isinstance(actual_digest, Mapping):
            return f"{stream}_missing"
        reason = _digest_failure_reason(stream, expected_digest, actual_digest)
        if reason is not None:
            return reason
    if expected.get("created_files") != actual.get("created_files"):
        return "created_files"
    return None


def _digest_failure_reason(stream: str, expected: Mapping[str, object], actual: Mapping[str, object]) -> str | None:
    for field in ("sha256", "size"):
        if expected.get(field) != actual.get(field):
            return f"{stream}_{field}"
    return None


def _semantic_run_matches(baseline: object, baseline_runtime: object, run: object) -> bool:
    """Require native runtime parity and use emulation when it supports both files."""
    if not isinstance(baseline, Mapping) or not isinstance(baseline_runtime, Mapping):
        return False
    if not isinstance(run, Mapping) or run.get("status") != "passed":
        return False
    if not _runtime_observables_equal(baseline_runtime, run.get("runtime")):
        return False
    unicorn = run.get("unicorn")
    if baseline.get("status") == "completed" and isinstance(unicorn, Mapping) and unicorn.get("status") == "completed":
        return unicorn.get("exit_code") == baseline.get("exit_code")
    return True


def _build_mutation_pass(pass_name: str, seed: int) -> MutationPass:
    pass_type = _PASS_TYPES.get(pass_name)
    if pass_type is None:
        raise ValueError(f"unsupported corpus pass: {pass_name}")
    return pass_type(config={"probability": 1.0, "seed": seed})


def _transformation_evidence(
    status: str,
    stats: object,
    error: object = None,
    pass_name: str = DEFAULT_MUTATION_NAME,
) -> dict[str, object]:
    """Describe whether the selected pass changed the fixture and why not."""
    label = _PASS_LABELS.get(pass_name, pass_name)
    if status == "error":
        if isinstance(error, Mapping):
            reason = error.get("error") or error.get("error_type") or "transformation failed"
        else:
            reason = "transformation failed"
        return {"pass_name": label, "status": "error", "reason": str(reason)}

    if not isinstance(stats, Mapping):
        return {"pass_name": label, "status": "omitted", "reason": "no pass statistics"}
    count_field = next(
        (field for field in _APPLIED_COUNT_FIELDS if isinstance(stats.get(field), int) and stats[field] > 0),
        None,
    )
    if count_field is not None:
        return {
            "pass_name": label,
            "status": "applied",
            count_field: stats[count_field],
        }
    for diagnostic_field in ("unsupported_functions", "partial_virtualization"):
        diagnostics = stats.get(diagnostic_field)
        if isinstance(diagnostics, list) and diagnostics and isinstance(diagnostics[0], Mapping):
            capability = diagnostics[0].get("capability", "unsupported capability")
            reason = diagnostics[0].get("reason", "pass precondition was not met")
            evidence = {
                "pass_name": label,
                "status": "omitted",
                "reason": f"{capability}: {reason}",
            }
            severity = diagnostics[0].get("severity")
            if isinstance(severity, str) and severity:
                evidence["severity"] = severity
            return evidence
    return {
        "pass_name": label,
        "status": "omitted",
        "reason": "no eligible function was transformed",
    }


def _diagnostic_counts(records: object, field: str) -> dict[str, int]:
    if not isinstance(records, list):
        return {}
    counts: dict[str, int] = {}
    for record in records:
        if not isinstance(record, Mapping):
            continue
        value = record.get(field)
        if isinstance(value, str) and value:
            counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _instruction_mnemonic(disassembly: object) -> str | None:
    if not isinstance(disassembly, str):
        return None
    tokens = disassembly.strip().lower().split()
    if not tokens:
        return None
    while tokens and tokens[0] in {"lock", "rep", "repe", "repne", "rex"}:
        tokens.pop(0)
    return tokens[0].rstrip(",") if tokens else None


def _affected_instruction_evidence(records: object) -> dict[str, object]:
    """Retain a bounded mnemonic catalogue from applied mutation records."""
    if not isinstance(records, list):
        return {
            "affected_instruction_evidence_status": "missing",
            "affected_instruction_mnemonics": [],
            "affected_instruction_record_count": 0,
        }
    mnemonics: set[str] = set()
    record_count = 0
    for record in records:
        disassembly = (
            record.get("original_disasm") if isinstance(record, Mapping) else getattr(record, "original_disasm", None)
        )
        mnemonic = _instruction_mnemonic(disassembly)
        metadata = record.get("metadata") if isinstance(record, Mapping) else getattr(record, "metadata", None)
        metadata_mnemonics = metadata.get("affected_instruction_mnemonics") if isinstance(metadata, Mapping) else None
        recorded_mnemonics = (
            {item.lower() for item in metadata_mnemonics if isinstance(item, str) and item}
            if isinstance(metadata_mnemonics, list)
            else set()
        )
        if mnemonic is None and not recorded_mnemonics:
            continue
        record_count += 1
        if len(mnemonics) < _MAX_AFFECTED_INSTRUCTION_MNEMONICS:
            mnemonics.update(recorded_mnemonics)
        if mnemonic is not None and len(mnemonics) < _MAX_AFFECTED_INSTRUCTION_MNEMONICS:
            mnemonics.add(mnemonic)
    return {
        "affected_instruction_evidence_status": "complete" if record_count else "missing",
        "affected_instruction_mnemonics": sorted(mnemonics),
        "affected_instruction_record_count": record_count,
    }


def _measure_seed(
    fixture: Path,
    seed: int,
    output_dir: Path,
    pass_name: str,
    runtime_inputs: tuple[tuple[str, ...], ...] = _DEFAULT_RUNTIME_INPUTS,
) -> dict[str, object]:
    output = output_dir / f"seed-{seed}"
    shutil.copyfile(fixture, output)
    started = time.perf_counter()
    mutation_records: object = []
    try:
        binary = Binary(output, writable=True)
        binary.open()
        try:
            binary.analyze("aa")
            mutation_pass = _build_mutation_pass(pass_name, seed)
            stats = mutation_pass.apply(binary)
            mutation_records = mutation_pass.get_records()
            evidence = _transformation_evidence("passed", stats, pass_name=pass_name)
            if evidence["status"] == "applied" or mutation_pass.get_records():
                binary.save()
        finally:
            binary.close()
        status = "passed"
        error: dict[str, object] = {}
        if evidence["status"] != "applied" and not mutation_pass.get_records():
            shutil.copyfile(fixture, output)
    except Exception as error_value:  # Measurement boundary records per-fixture failures.
        stats = {}
        status = "error"
        error = {"error_type": type(error_value).__name__, "error": str(error_value)}

    run: dict[str, object] = {
        "seed": seed,
        "status": status,
        "transformation": _transformation_evidence(status, stats, error if status == "error" else None, pass_name),
        "output_sha256": sha256(output),
        "output_size": output.stat().st_size,
        "transform_duration_seconds": time.perf_counter() - started,
        "runtime": _runtime_artifacts(output),
        "runtime_inputs": _runtime_input_artifacts(output, runtime_inputs),
        "unicorn": _semantic_artifacts(output),
    }
    run.update(_affected_instruction_evidence(mutation_records))
    if status == "passed":
        run.update(
            {
                "functions_virtualized": stats.get("functions_virtualized", 0),
                "mutations_applied": stats.get("mutations_applied", 0),
                "total_instructions": stats.get("total_instructions", 0),
                "total_bytecode_bytes": stats.get("total_bytecode_bytes", 0),
                "after": _safe_inspect(output),
            }
        )
        for source, prefix in (
            (stats.get("unsupported_functions"), "unsupported"),
            (stats.get("partial_virtualization"), "partial_virtualization"),
        ):
            capabilities = _diagnostic_counts(source, "capability")
            severities = _diagnostic_counts(source, "severity")
            if capabilities:
                run[f"{prefix}_capabilities"] = capabilities
            if severities:
                run[f"{prefix}_severities"] = severities
    else:
        run["error"] = error
    return run


def measure_fixture(
    fixture: Path,
    seeds: range,
    output_root: Path,
    pass_name: str = DEFAULT_MUTATION_NAME,
    runtime_inputs: tuple[tuple[str, ...], ...] = _DEFAULT_RUNTIME_INPUTS,
) -> dict[str, object]:
    baseline_runtime = _runtime_artifacts(fixture)
    baseline_runtime_inputs = _runtime_input_artifacts(fixture, runtime_inputs)
    baseline_unicorn = _semantic_artifacts(fixture)
    baseline = _safe_inspect(fixture)
    output_dir = output_root / _PASS_LABELS[pass_name] / fixture.name
    output_dir.mkdir(parents=True)
    runs = [_measure_seed(fixture, seed, output_dir, pass_name, runtime_inputs) for seed in seeds]
    semantic_runs = []
    for run in runs:
        runtime_equal = _runtime_observables_equal(baseline_runtime, run.get("runtime"))
        runtime_input_equal = _runtime_input_observables_equal(baseline_runtime_inputs, run.get("runtime_inputs"))
        run["runtime_observable_equal"] = runtime_equal
        run["runtime_input_observable_equal"] = runtime_input_equal
        if runtime_input_equal and _semantic_run_matches(baseline_unicorn, baseline_runtime, run):
            semantic_runs.append(run)
    return {
        "sample": fixture.name,
        "baseline_sha256": sha256(fixture),
        "baseline_size": fixture.stat().st_size,
        "baseline": baseline,
        "baseline_runtime": baseline_runtime,
        "baseline_runtime_inputs": baseline_runtime_inputs,
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


def build_generated_corpus(output_dir: Path) -> list[Path]:
    """Build compiler and relocation variants of synthetic ELF x86-64 fixtures."""
    if not sys.platform.startswith("linux"):
        raise RuntimeError("generated ELF corpus requires a Linux x86-64 toolchain")
    output_dir.mkdir(parents=True, exist_ok=True)
    fixtures: list[Path] = []
    for name, source_text in _GENERATED_CORPUS_SOURCES.items():
        cpp_source = name == "generated_cpp"
        source = output_dir / f"{name}{'.cpp' if cpp_source else '.c'}"
        source.write_text(f"{_GENERATED_UNREACHABLE_PADDING}\n{source_text}", encoding="utf-8")
        profiles = _GENERATED_CPP_CORPUS_PROFILES if cpp_source else _GENERATED_CORPUS_PROFILES
        for profile, compiler, optimization, *linker_flags in profiles:
            if shutil.which(compiler) is None:
                raise RuntimeError(f"required generated corpus compiler is unavailable: {compiler}")
            binary = output_dir / f"{name}_{profile}"
            command = [
                compiler,
                optimization,
                *linker_flags,
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-fno-stack-protector",
                source.as_posix(),
                "-o",
                binary.as_posix(),
            ]
            result = run_process(command, timeout=30)
            if result.returncode != 0:
                raise RuntimeError(
                    f"failed to compile generated corpus fixture {binary.name}: {result.stderr_text.strip()}"
                )
            fixtures.append(binary)
    executables = discover_executables(output_dir)
    if len(executables) != len(fixtures):
        raise RuntimeError("generated corpus did not produce ELF x86-64 executable fixtures")
    return executables


def _static_metric_deltas(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    deltas: dict[str, int] = {}
    for fixture, run in seed_runs:
        baseline = fixture.get("baseline")
        after = run.get("after")
        if not isinstance(baseline, Mapping) or not isinstance(after, Mapping):
            continue
        baseline_metrics = baseline.get("metrics")
        after_metrics = after.get("metrics")
        if not isinstance(baseline_metrics, Mapping) or not isinstance(after_metrics, Mapping):
            continue
        for key, baseline_value in baseline_metrics.items():
            after_value = after_metrics.get(key)
            if key.startswith("number_of_") and isinstance(baseline_value, int) and isinstance(after_value, int):
                deltas[f"total_static_{key}_delta"] = deltas.get(f"total_static_{key}_delta", 0) + (
                    after_value - baseline_value
                )
    return deltas


def _has_static_metrics(value: object) -> bool:
    return (
        isinstance(value, Mapping) and value.get("status") == "completed" and isinstance(value.get("metrics"), Mapping)
    )


def _static_metric_coverage(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    complete = sum(
        1
        for fixture, run in seed_runs
        if _has_static_metrics(fixture.get("baseline")) and _has_static_metrics(run.get("after"))
    )
    return {
        "static_metric_complete_runs": complete,
        "static_metric_missing_runs": len(seed_runs) - complete,
    }


def _has_completed_runtime(value: object) -> bool:
    return isinstance(value, Mapping) and value.get("status") == "completed"


def _runtime_observable_coverage(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    complete = sum(
        1
        for fixture, run in seed_runs
        if _has_completed_runtime(fixture.get("baseline_runtime")) and _has_completed_runtime(run.get("runtime"))
    )
    return {
        "runtime_observable_complete_runs": complete,
        "runtime_observable_missing_runs": len(seed_runs) - complete,
    }


def _runtime_observable_failure_reasons(
    seed_runs: list[tuple[dict[str, object], Mapping[str, object]]],
) -> dict[str, int]:
    reasons: dict[str, int] = {}
    for fixture, run in seed_runs:
        if run.get("runtime_observable_equal") is not False:
            continue
        reason = _runtime_observable_failure_reason(fixture.get("baseline_runtime"), run.get("runtime"))
        key = reason or "unspecified"
        reasons[key] = reasons.get(key, 0) + 1
    return dict(sorted(reasons.items()))


def _behavioral_false_positive_metrics(
    seed_runs: list[tuple[dict[str, object], Mapping[str, object]]],
) -> dict[str, int | float]:
    """Measure applied mutations against native and independent VM observables."""
    complete_observations = 0
    false_positive_observations = 0
    missing_observations = 0
    independent_observations = 0
    independent_false_positive_observations = 0
    independent_missing_observations = 0
    for fixture, run in seed_runs:
        transformation = run.get("transformation")
        if not isinstance(transformation, Mapping) or transformation.get("status") != "applied":
            continue
        baseline_inputs = fixture.get("baseline_runtime_inputs")
        run_inputs = run.get("runtime_inputs")
        if not isinstance(baseline_inputs, list) or not isinstance(run_inputs, list):
            missing_observations += 1
            continue
        if len(baseline_inputs) != len(run_inputs) or not baseline_inputs:
            missing_observations += 1
            continue
        for baseline, actual in zip(baseline_inputs, run_inputs, strict=True):
            if not isinstance(baseline, Mapping) or not isinstance(actual, Mapping):
                missing_observations += 1
                continue
            if baseline.get("status") != "completed" or actual.get("status") != "completed":
                missing_observations += 1
                continue
            complete_observations += 1
            if not _runtime_observables_equal(baseline, actual):
                false_positive_observations += 1
        baseline_unicorn = fixture.get("baseline_unicorn")
        actual_unicorn = run.get("unicorn")
        if not isinstance(baseline_unicorn, Mapping) or baseline_unicorn.get("status") != "completed":
            continue
        if not isinstance(actual_unicorn, Mapping) or actual_unicorn.get("status") != "completed":
            independent_missing_observations += 1
            continue
        independent_observations += 1
        if baseline_unicorn.get("exit_code") != actual_unicorn.get("exit_code"):
            independent_false_positive_observations += 1
    rate = round(false_positive_observations / complete_observations * 100.0, 2) if complete_observations else 0.0
    independent_rate = (
        round(independent_false_positive_observations / independent_observations * 100.0, 2)
        if independent_observations
        else 0.0
    )
    return {
        "behavioral_validation_observations": complete_observations,
        "behavioral_false_positive_observations": false_positive_observations,
        "behavioral_validation_missing_observations": missing_observations,
        "behavioral_false_positive_rate_percent": rate,
        "independent_semantic_observations": independent_observations,
        "independent_semantic_false_positive_observations": independent_false_positive_observations,
        "independent_semantic_missing_observations": independent_missing_observations,
        "independent_semantic_false_positive_rate_percent": independent_rate,
    }


def _numeric_metric_coverage(
    seed_runs: list[tuple[dict[str, object], Mapping[str, object]]],
    summary_prefix: str,
    baseline_field: str | None,
    run_field: str,
) -> dict[str, int]:
    complete = sum(
        1
        for fixture, run in seed_runs
        if (baseline_field is None or isinstance(fixture.get(baseline_field), int | float))
        and isinstance(run.get(run_field), int | float)
    )
    return {
        f"{summary_prefix}_complete_runs": complete,
        f"{summary_prefix}_missing_runs": len(seed_runs) - complete,
    }


def _runtime_duration_coverage(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    complete = sum(
        1
        for fixture, run in seed_runs
        if isinstance(baseline_runtime := fixture.get("baseline_runtime"), Mapping)
        and isinstance(runtime := run.get("runtime"), Mapping)
        and isinstance(baseline_runtime.get("duration_seconds"), int | float)
        and isinstance(runtime.get("duration_seconds"), int | float)
    )
    return {
        "runtime_duration_complete_runs": complete,
        "runtime_duration_missing_runs": len(seed_runs) - complete,
    }


def _complete_evidence_coverage(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    complete = sum(1 for fixture, run in seed_runs if _has_complete_evidence(fixture, run))
    return {
        "complete_evidence_runs": complete,
        "complete_evidence_missing_runs": len(seed_runs) - complete,
    }


def _has_complete_evidence(fixture: dict[str, object], run: Mapping[str, object]) -> bool:
    baseline_runtime = fixture.get("baseline_runtime")
    runtime = run.get("runtime")
    return (
        _has_completed_runtime(baseline_runtime)
        and _has_completed_runtime(runtime)
        and isinstance(fixture.get("baseline_size"), int)
        and isinstance(run.get("output_size"), int)
        and isinstance(run.get("transform_duration_seconds"), int | float)
        and isinstance(baseline_runtime, Mapping)
        and isinstance(runtime, Mapping)
        and isinstance(baseline_runtime.get("duration_seconds"), int | float)
        and isinstance(runtime.get("duration_seconds"), int | float)
        and _has_static_metrics(fixture.get("baseline"))
        and _has_static_metrics(run.get("after"))
    )


def _coverage_percent(complete: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(complete / total * 100.0, 2)


def _transformation_reason_counts(
    seed_runs: list[tuple[dict[str, object], Mapping[str, object]]], status: str
) -> dict[str, int]:
    reasons: dict[str, int] = {}
    for _, run in seed_runs:
        transformation = run.get("transformation")
        if not isinstance(transformation, Mapping) or transformation.get("status") != status:
            continue
        reason = str(transformation.get("reason", "unspecified"))
        reasons[reason] = reasons.get(reason, 0) + 1
    return dict(sorted(reasons.items()))


def _transformation_severity_counts(
    seed_runs: list[tuple[dict[str, object], Mapping[str, object]]], status: str
) -> dict[str, int]:
    severities: dict[str, int] = {}
    for _, run in seed_runs:
        transformation = run.get("transformation")
        if not isinstance(transformation, Mapping) or transformation.get("status") != status:
            continue
        severity = transformation.get("severity")
        if isinstance(severity, str) and severity:
            severities[severity] = severities.get(severity, 0) + 1
    return dict(sorted(severities.items()))


def _render_result(fixtures: list[dict[str, object]], pass_name: str = DEFAULT_MUTATION_NAME) -> dict[str, object]:
    seed_runs = [(fixture, run) for fixture in fixtures for run in fixture.get("runs", []) if isinstance(run, Mapping)]
    successful_seed_runs = sum(
        value if isinstance(value := fixture.get("successful_runs"), int) else 0 for fixture in fixtures
    )
    failed_seed_runs = sum(value if isinstance(value := fixture.get("failed_runs"), int) else 0 for fixture in fixtures)
    applied_runs = sum(
        1
        for _, run in seed_runs
        if isinstance(transformation := run.get("transformation"), Mapping)
        and transformation.get("status") == "applied"
    )
    omitted_runs = sum(
        1
        for _, run in seed_runs
        if isinstance(transformation := run.get("transformation"), Mapping)
        and transformation.get("status") == "omitted"
    )
    error_runs = sum(
        1
        for _, run in seed_runs
        if isinstance(transformation := run.get("transformation"), Mapping) and transformation.get("status") == "error"
    )
    output_size_delta_bytes = sum(
        run["output_size"] - fixture["baseline_size"]
        for fixture, run in seed_runs
        if isinstance(fixture.get("baseline_size"), int) and isinstance(run.get("output_size"), int)
    )
    transform_duration_seconds = sum(
        duration for _, run in seed_runs if isinstance(duration := run.get("transform_duration_seconds"), int | float)
    )
    runtime_duration_delta_seconds = sum(
        runtime["duration_seconds"] - baseline_runtime["duration_seconds"]
        for fixture, run in seed_runs
        if isinstance(baseline_runtime := fixture.get("baseline_runtime"), Mapping)
        and isinstance(runtime := run.get("runtime"), Mapping)
        and isinstance(baseline_runtime.get("duration_seconds"), int | float)
        and isinstance(runtime.get("duration_seconds"), int | float)
    )
    runtime_observable_passes = sum(1 for _, run in seed_runs if run.get("runtime_observable_equal") is True)
    runtime_observable_failures = sum(1 for _, run in seed_runs if run.get("runtime_observable_equal") is False)
    behavioral_false_positive_metrics = _behavioral_false_positive_metrics(seed_runs)
    output_size_deltas = tuple(
        run["output_size"] - fixture["baseline_size"]
        for fixture, run in seed_runs
        if isinstance(fixture.get("baseline_size"), int) and isinstance(run.get("output_size"), int)
    )
    runtime_observable_coverage = _runtime_observable_coverage(seed_runs)
    runtime_observable_failure_reasons = _runtime_observable_failure_reasons(seed_runs)
    output_size_coverage = _numeric_metric_coverage(seed_runs, "output_size", "baseline_size", "output_size")
    transform_duration_coverage = _numeric_metric_coverage(
        seed_runs,
        "transform_duration",
        None,
        "transform_duration_seconds",
    )
    runtime_duration_coverage = _runtime_duration_coverage(seed_runs)
    static_metric_deltas = _static_metric_deltas(seed_runs)
    static_metric_coverage = _static_metric_coverage(seed_runs)
    complete_evidence_coverage = _complete_evidence_coverage(seed_runs)
    seed_run_count = len(seed_runs)
    omission_reasons = _transformation_reason_counts(seed_runs, "omitted")
    error_reasons = _transformation_reason_counts(seed_runs, "error")
    omission_severities = _transformation_severity_counts(seed_runs, "omitted")
    error_severities = _transformation_severity_counts(seed_runs, "error")
    affected_instruction_complete_runs = sum(
        1
        for _, run in seed_runs
        if isinstance(transformation := run.get("transformation"), Mapping)
        and transformation.get("status") == "applied"
        and run.get("affected_instruction_evidence_status") == "complete"
    )
    affected_instruction_applied_runs = sum(
        1
        for _, run in seed_runs
        if isinstance(transformation := run.get("transformation"), Mapping)
        and transformation.get("status") == "applied"
    )
    affected_instruction_mnemonics = sorted(
        {
            mnemonic
            for _, run in seed_runs
            for mnemonic in run.get("affected_instruction_mnemonics", [])
            if isinstance(mnemonic, str)
        }
    )
    affected_instruction_record_count = sum(
        value for _, run in seed_runs if isinstance(value := run.get("affected_instruction_record_count"), int)
    )
    return {
        "schema_version": 2,
        "measurement": "protection-maturity-corpus",
        "pass_name": pass_name,
        "compatible_fixture_count": len(fixtures),
        "fixtures": fixtures,
        "summary": {
            "semantic_passes": sum(1 for fixture in fixtures if fixture["all_semantic_equal"]),
            "semantic_failures": sum(1 for fixture in fixtures if not fixture["all_semantic_equal"]),
            "successful_seed_runs": successful_seed_runs,
            "failed_seed_runs": failed_seed_runs,
            "applied_runs": applied_runs,
            "omitted_runs": omitted_runs,
            "error_runs": error_runs,
            "runtime_observable_passes": runtime_observable_passes,
            "runtime_observable_failures": runtime_observable_failures,
            "runtime_observable_failure_reasons": runtime_observable_failure_reasons,
            **behavioral_false_positive_metrics,
            **runtime_observable_coverage,
            "runtime_observable_coverage_percent": _coverage_percent(
                runtime_observable_coverage["runtime_observable_complete_runs"],
                seed_run_count,
            ),
            **output_size_coverage,
            "output_size_coverage_percent": _coverage_percent(
                output_size_coverage["output_size_complete_runs"],
                seed_run_count,
            ),
            "total_output_size_delta_bytes": output_size_delta_bytes,
            "max_output_size_delta_bytes": max(output_size_deltas, default=0),
            "min_output_size_delta_bytes": min(output_size_deltas, default=0),
            **transform_duration_coverage,
            "transform_duration_coverage_percent": _coverage_percent(
                transform_duration_coverage["transform_duration_complete_runs"],
                seed_run_count,
            ),
            "total_transform_duration_seconds": transform_duration_seconds,
            **runtime_duration_coverage,
            "runtime_duration_coverage_percent": _coverage_percent(
                runtime_duration_coverage["runtime_duration_complete_runs"],
                seed_run_count,
            ),
            "total_runtime_duration_delta_seconds": runtime_duration_delta_seconds,
            "omission_reasons": omission_reasons,
            "error_reasons": error_reasons,
            "omission_severities": omission_severities,
            "error_severities": error_severities,
            "affected_instruction_applied_runs": affected_instruction_applied_runs,
            "affected_instruction_complete_runs": affected_instruction_complete_runs,
            "affected_instruction_missing_runs": affected_instruction_applied_runs - affected_instruction_complete_runs,
            "affected_instruction_coverage_percent": _coverage_percent(
                affected_instruction_complete_runs,
                affected_instruction_applied_runs,
            ),
            "affected_instruction_mnemonics": affected_instruction_mnemonics,
            "affected_instruction_record_count": affected_instruction_record_count,
            **static_metric_coverage,
            "static_metric_coverage_percent": _coverage_percent(
                static_metric_coverage["static_metric_complete_runs"],
                seed_run_count,
            ),
            **complete_evidence_coverage,
            "complete_evidence_coverage_percent": _coverage_percent(
                complete_evidence_coverage["complete_evidence_runs"],
                seed_run_count,
            ),
            **static_metric_deltas,
        },
    }


def _parse_pass_names(value: str) -> tuple[str, ...]:
    if value.strip().lower() == "all":
        return CORPUS_PASS_NAMES
    names = tuple(item.strip() for item in value.split(",") if item.strip())
    if not names or any(name not in _PASS_TYPES for name in names):
        valid = ", ".join((*sorted(_PASS_TYPES), "all"))
        raise ValueError(f"unknown pass in {value!r}; choose from {valid}")
    if len(set(names)) != len(names):
        raise ValueError("--passes must not contain duplicates")
    return names


def _render_multi_pass_result(
    measurements: dict[str, list[dict[str, object]]],
    dataset: Path | None = None,
    corpus_families: list[str] | None = None,
    corpus_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    metadata = corpus_metadata or {}
    generated_fixture_count = metadata.get("generated_fixture_count", 0)
    generated_fixture_names = metadata.get("generated_fixture_names", [])
    fixture_shard = metadata.get("fixture_shard")
    rendered = {name: _render_result(fixtures, name) for name, fixtures in measurements.items()}
    summaries = {name: result["summary"] for name, result in rendered.items()}
    campaign_summary = _multi_pass_campaign_summary(summaries)
    input_sources = _runtime_input_sources(measurements)
    campaign_summary["platform_scope"] = dict(_DIFFERENTIAL_PLATFORM_SCOPE)
    campaign_summary["platform_gap_scope"] = dict(_DIFFERENTIAL_PLATFORM_GAP_SCOPE)
    campaign_summary["input_sources"] = input_sources
    campaign_summary["corpus_families"] = list(corpus_families or ["repository-fixtures"])
    campaign_summary["generated_fixture_count"] = generated_fixture_count
    campaign_summary["generated_fixture_names"] = list(generated_fixture_names or [])
    campaign_summary["corpus_gap_scope"] = _differential_corpus_gap_scope(
        input_sources,
        campaign_summary["corpus_families"],
    )
    campaign_summary["corpus_scope"] = {"dataset": dataset.as_posix() if dataset is not None else "explicit-fixtures"}
    if isinstance(fixture_shard, dict):
        campaign_summary["corpus_scope"]["fixture_shard"] = dict(fixture_shard)
    campaign_summary["continuous_evidence_blockers"] = _continuous_evidence_blockers(campaign_summary)
    campaign_summary["continuous_evidence_blocker_totals"] = _continuous_evidence_blocker_totals(
        campaign_summary["continuous_evidence_blockers"]
    )
    return {
        "schema_version": 3,
        "measurement": "protection-maturity-corpus-by-pass",
        "pass_names": list(rendered),
        "passes": rendered,
        "summary": summaries,
        "campaign_summary": campaign_summary,
    }


def _report_campaign_metadata(report: Mapping[str, object]) -> tuple[set[str], set[str], Path | None]:
    families: set[str] = set()
    generated_fixture_names: set[str] = set()
    dataset: Path | None = None
    campaign_summary = report.get("campaign_summary")
    if not isinstance(campaign_summary, Mapping):
        return families, generated_fixture_names, dataset
    family_values = campaign_summary.get("corpus_families")
    if isinstance(family_values, list):
        families.update(value for value in family_values if isinstance(value, str))
    generated_values = campaign_summary.get("generated_fixture_names")
    if isinstance(generated_values, list):
        generated_fixture_names.update(value for value in generated_values if isinstance(value, str))
    scope = campaign_summary.get("corpus_scope")
    if isinstance(scope, Mapping) and isinstance(value := scope.get("dataset"), str):
        dataset = Path(value)
    return families, generated_fixture_names, dataset


def _report_pass_fixtures(
    pass_name: str,
    pass_report: object,
    seen_fixture_runs: set[tuple[str, str, tuple[str, ...]]],
) -> list[dict[str, object]]:
    if not isinstance(pass_report, Mapping):
        raise ValueError(f"maturity report is missing pass result: {pass_name}")
    fixtures = pass_report.get("fixtures")
    if not isinstance(fixtures, list) or not all(isinstance(fixture, dict) for fixture in fixtures):
        raise ValueError(f"maturity report has invalid fixtures for pass: {pass_name}")
    for fixture in fixtures:
        sample = fixture.get("sample")
        seeds = fixture.get("seeds")
        if not isinstance(sample, str) or not isinstance(seeds, list):
            continue
        fixture_key = (pass_name, sample, tuple(str(seed) for seed in seeds))
        if fixture_key in seen_fixture_runs:
            raise ValueError(f"maturity reports overlap fixture runs: {sample}")
        seen_fixture_runs.add(fixture_key)
    return fixtures


def merge_maturity_reports(reports: list[Mapping[str, object]]) -> dict[str, object]:
    """Merge disjoint corpus reports before evaluating campaign-wide gates."""
    if not reports:
        raise ValueError("at least one maturity report is required")
    first_passes = reports[0].get("passes")
    if not isinstance(first_passes, Mapping):
        raise ValueError("maturity report is missing pass results")
    pass_names = tuple(str(name) for name in first_passes)
    measurements: dict[str, list[dict[str, object]]] = {name: [] for name in pass_names}
    corpus_families: set[str] = set()
    generated_fixture_names: set[str] = set()
    seen_fixture_runs: set[tuple[str, str, tuple[str, ...]]] = set()
    dataset: Path | None = None
    for report in reports:
        passes = report.get("passes")
        if not isinstance(passes, Mapping) or tuple(str(name) for name in passes) != pass_names:
            raise ValueError("maturity reports do not contain the same pass set")
        families, generated, report_dataset = _report_campaign_metadata(report)
        corpus_families.update(families)
        generated_fixture_names.update(generated)
        dataset = report_dataset or dataset
        for pass_name in pass_names:
            measurements[pass_name].extend(_report_pass_fixtures(pass_name, passes.get(pass_name), seen_fixture_runs))
    return _render_multi_pass_result(
        measurements,
        dataset,
        sorted(corpus_families),
        {
            "generated_fixture_count": len(generated_fixture_names),
            "generated_fixture_names": sorted(generated_fixture_names),
        },
    )


def _runtime_input_sources(measurements: dict[str, list[dict[str, object]]]) -> list[str]:
    generated = any(
        isinstance(inputs := fixture.get("baseline_runtime_inputs"), list) and len(inputs) > 1
        for fixtures in measurements.values()
        for fixture in fixtures
    )
    return [_DEFAULT_INPUT_SOURCE, _GENERATED_INPUT_SOURCE] if generated else [_DEFAULT_INPUT_SOURCE]


def _differential_corpus_gap_scope(
    input_sources: list[str],
    corpus_families: list[str],
) -> dict[str, list[str]]:
    generated_families = {_GENERATED_CORPUS_FAMILY, _GENERATED_CPP_CORPUS_FAMILY}
    return {
        "corpus_families": (
            []
            if generated_families.issubset(corpus_families)
            else list(_DIFFERENTIAL_CORPUS_GAP_SCOPE["corpus_families"])
        ),
        "input_sources": [] if _GENERATED_INPUT_SOURCE in input_sources else ["generated-inputs"],
    }


def _average_percent(summaries: dict[str, object], field: str) -> float:
    values = [
        summary[field]
        for summary in summaries.values()
        if isinstance(summary, dict) and isinstance(summary.get(field), int | float)
    ]
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)


def _sum_summary_field(summaries: dict[str, object], field: str) -> int:
    return sum(
        value
        for summary in summaries.values()
        if isinstance(summary, dict) and isinstance(value := summary.get(field), int)
    )


def _sum_numeric_summary_field(summaries: dict[str, object], field: str) -> int | float:
    total: int | float = 0
    for summary in summaries.values():
        if isinstance(summary, dict) and isinstance(value := summary.get(field), int | float):
            total += value
    return total


def _sum_static_delta_fields(summaries: dict[str, object]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for summary in summaries.values():
        if not isinstance(summary, dict):
            continue
        for field, value in summary.items():
            if field.startswith("total_static_") and field.endswith("_delta") and isinstance(value, int):
                totals[field] = totals.get(field, 0) + value
    return dict(sorted(totals.items()))


def _multi_pass_campaign_summary(summaries: dict[str, object]) -> dict[str, object]:
    selected_passes = set(summaries)
    corpus_passes = set(CORPUS_PASS_NAMES)
    extended_passes = set(EXTENDED_MATURITY_PASS_NAMES)
    selected_extended_passes = selected_passes & extended_passes
    total_applied_runs = _sum_summary_field(summaries, "applied_runs")
    total_omitted_runs = _sum_summary_field(summaries, "omitted_runs")
    total_error_runs = _sum_summary_field(summaries, "error_runs")
    total_classified_runs = total_applied_runs + total_omitted_runs + total_error_runs
    total_successful_seed_runs = _sum_summary_field(summaries, "successful_seed_runs")
    total_failed_seed_runs = _sum_summary_field(summaries, "failed_seed_runs")
    total_seed_runs = total_successful_seed_runs + total_failed_seed_runs
    summary = {
        "pass_count": len(summaries),
        "expected_corpus_pass_count": len(CORPUS_PASS_NAMES),
        "covered_corpus_pass_count": len(selected_passes & corpus_passes),
        "corpus_pass_coverage_percent": _coverage_percent(len(selected_passes & corpus_passes), len(CORPUS_PASS_NAMES)),
        "missing_corpus_passes": sorted(corpus_passes - selected_passes),
        "expected_extended_pass_count": len(EXTENDED_MATURITY_PASS_NAMES),
        "covered_extended_pass_count": len(selected_extended_passes),
        "extended_pass_coverage_percent": _coverage_percent(
            len(selected_extended_passes),
            len(EXTENDED_MATURITY_PASS_NAMES),
        ),
        "missing_extended_passes": sorted(extended_passes - selected_passes),
        "passes_without_applied_runs": _passes_with_zero_runs(summaries, "applied_runs"),
        "passes_without_extended_applied_runs": sorted(
            selected_extended_passes & set(_passes_with_zero_runs(summaries, "applied_runs"))
        ),
        "passes_with_omitted_runs": _passes_with_positive_runs(summaries, "omitted_runs"),
        "passes_with_error_runs": _passes_with_positive_runs(summaries, "error_runs"),
        "extended_passes_with_error_runs": sorted(
            selected_extended_passes & set(_passes_with_positive_runs(summaries, "error_runs"))
        ),
        "passes_with_incomplete_coverage": _passes_with_incomplete_coverage(summaries),
        "metric_complete_runs": _metric_run_totals(summaries, _COMPLETE_RUN_FIELD),
        "metric_missing_runs": _metric_run_totals(summaries, _MISSING_RUN_FIELD),
        "passes_with_semantic_failures": _passes_with_positive_runs(summaries, "semantic_failures"),
        "passes_with_runtime_observable_failures": _passes_with_positive_runs(
            summaries,
            "runtime_observable_failures",
        ),
        "passes_with_behavioral_false_positives": _passes_with_positive_runs(
            summaries,
            "behavioral_false_positive_observations",
        ),
        "passes_with_independent_semantic_false_positives": _passes_with_positive_runs(
            summaries,
            "independent_semantic_false_positive_observations",
        ),
        "passes_with_missing_affected_instruction_evidence": _passes_with_positive_runs(
            summaries,
            "affected_instruction_missing_runs",
        ),
        "affected_instruction_complete_runs": _sum_summary_field(
            summaries,
            "affected_instruction_complete_runs",
        ),
        "affected_instruction_applied_runs": _sum_summary_field(
            summaries,
            "affected_instruction_applied_runs",
        ),
        "affected_instruction_missing_runs": _sum_summary_field(
            summaries,
            "affected_instruction_missing_runs",
        ),
        "affected_instruction_mnemonics_by_pass": {
            name: summary["affected_instruction_mnemonics"]
            for name, summary in summaries.items()
            if isinstance(summary, dict) and isinstance(summary.get("affected_instruction_mnemonics"), list)
        },
        "behavioral_false_positive_rate_percent_by_pass": {
            name: summary["behavioral_false_positive_rate_percent"]
            for name, summary in summaries.items()
            if isinstance(summary, dict)
            and isinstance(summary.get("behavioral_false_positive_rate_percent"), int | float)
        },
        "behavioral_validation_missing_observations_by_pass": {
            name: summary["behavioral_validation_missing_observations"]
            for name, summary in summaries.items()
            if isinstance(summary, dict)
            and isinstance(summary.get("behavioral_validation_missing_observations"), int)
            and summary["behavioral_validation_missing_observations"] > 0
        },
        "independent_semantic_observations_by_pass": {
            name: summary["independent_semantic_observations"]
            for name, summary in summaries.items()
            if isinstance(summary, dict) and isinstance(summary.get("independent_semantic_observations"), int)
        },
        "independent_semantic_missing_observations_by_pass": {
            name: summary["independent_semantic_missing_observations"]
            for name, summary in summaries.items()
            if isinstance(summary, dict)
            and isinstance(summary.get("independent_semantic_missing_observations"), int)
            and summary["independent_semantic_missing_observations"] > 0
        },
        "independent_semantic_false_positive_rate_percent_by_pass": {
            name: summary["independent_semantic_false_positive_rate_percent"]
            for name, summary in summaries.items()
            if isinstance(summary, dict)
            and isinstance(summary.get("independent_semantic_false_positive_rate_percent"), int | float)
        },
        "runtime_observable_failure_reasons_by_pass": _reason_map_by_pass(
            summaries,
            "runtime_observable_failure_reasons",
        ),
        "omission_reasons_by_pass": _reason_map_by_pass(summaries, "omission_reasons"),
        "error_reasons_by_pass": _reason_map_by_pass(summaries, "error_reasons"),
        "omission_severities_by_pass": _reason_map_by_pass(summaries, "omission_severities"),
        "error_severities_by_pass": _reason_map_by_pass(summaries, "error_severities"),
        "total_classified_runs": total_classified_runs,
        "total_applied_runs": total_applied_runs,
        "total_omitted_runs": total_omitted_runs,
        "total_error_runs": total_error_runs,
        "applied_run_percent": _coverage_percent(total_applied_runs, total_classified_runs),
        "omitted_run_percent": _coverage_percent(total_omitted_runs, total_classified_runs),
        "error_run_percent": _coverage_percent(total_error_runs, total_classified_runs),
        "total_seed_runs": total_seed_runs,
        "total_successful_seed_runs": total_successful_seed_runs,
        "total_failed_seed_runs": total_failed_seed_runs,
        "semantic_success_percent": _coverage_percent(total_successful_seed_runs, total_seed_runs),
        "semantic_failure_percent": _coverage_percent(total_failed_seed_runs, total_seed_runs),
        "average_runtime_observable_coverage_percent": _average_percent(
            summaries,
            "runtime_observable_coverage_percent",
        ),
        "total_runtime_observable_complete_runs": _sum_summary_field(
            summaries,
            "runtime_observable_complete_runs",
        ),
        "total_runtime_observable_missing_runs": _sum_summary_field(
            summaries,
            "runtime_observable_missing_runs",
        ),
        "average_output_size_coverage_percent": _average_percent(summaries, "output_size_coverage_percent"),
        "total_output_size_complete_runs": _sum_summary_field(summaries, "output_size_complete_runs"),
        "total_output_size_missing_runs": _sum_summary_field(summaries, "output_size_missing_runs"),
        "total_output_size_delta_bytes": _sum_summary_field(summaries, "total_output_size_delta_bytes"),
        "average_transform_duration_coverage_percent": _average_percent(
            summaries,
            "transform_duration_coverage_percent",
        ),
        "total_transform_duration_complete_runs": _sum_summary_field(
            summaries,
            "transform_duration_complete_runs",
        ),
        "total_transform_duration_missing_runs": _sum_summary_field(
            summaries,
            "transform_duration_missing_runs",
        ),
        "total_transform_duration_seconds": _sum_numeric_summary_field(
            summaries,
            "total_transform_duration_seconds",
        ),
        "average_runtime_duration_coverage_percent": _average_percent(
            summaries,
            "runtime_duration_coverage_percent",
        ),
        "total_runtime_duration_complete_runs": _sum_summary_field(summaries, "runtime_duration_complete_runs"),
        "total_runtime_duration_missing_runs": _sum_summary_field(summaries, "runtime_duration_missing_runs"),
        "total_runtime_duration_delta_seconds": _sum_numeric_summary_field(
            summaries,
            "total_runtime_duration_delta_seconds",
        ),
        "average_static_metric_coverage_percent": _average_percent(summaries, "static_metric_coverage_percent"),
        "total_static_metric_complete_runs": _sum_summary_field(summaries, "static_metric_complete_runs"),
        "total_static_metric_missing_runs": _sum_summary_field(summaries, "static_metric_missing_runs"),
        "average_complete_evidence_coverage_percent": _average_percent(
            summaries,
            "complete_evidence_coverage_percent",
        ),
        "total_complete_evidence_runs": _sum_summary_field(summaries, "complete_evidence_runs"),
        "total_complete_evidence_missing_runs": _sum_summary_field(summaries, "complete_evidence_missing_runs"),
        **_sum_static_delta_fields(summaries),
    }
    summary["extended_maturity_evidence_blockers"] = _extended_maturity_evidence_blockers(summary)
    summary["extended_maturity_evidence_blocker_totals"] = _extended_maturity_evidence_blocker_totals(
        summary["extended_maturity_evidence_blockers"]
    )
    summary["continuous_evidence_blockers"] = _continuous_evidence_blockers(summary)
    summary["continuous_evidence_blocker_totals"] = _continuous_evidence_blocker_totals(
        summary["continuous_evidence_blockers"]
    )
    return summary


def _extended_maturity_evidence_blockers(summary: Mapping[str, object]) -> dict[str, object]:
    blockers: dict[str, object] = {}
    for field in (
        "missing_extended_passes",
        "passes_without_extended_applied_runs",
        "extended_passes_with_error_runs",
    ):
        value = summary.get(field)
        if isinstance(value, list) and value:
            blockers[field] = value
    return blockers


def _extended_maturity_evidence_blocker_totals(blockers: Mapping[str, object]) -> dict[str, int]:
    totals = _continuous_evidence_blocker_totals(blockers)
    totals["total_extended_maturity_evidence_blockers"] = totals.pop("total_continuous_evidence_blockers")
    return totals


def _continuous_evidence_blockers(summary: Mapping[str, object]) -> dict[str, object]:
    blockers: dict[str, object] = {}
    for field in (
        "missing_corpus_passes",
        "metric_missing_runs",
        "passes_without_applied_runs",
        "passes_with_error_runs",
        "passes_with_incomplete_coverage",
        "passes_with_semantic_failures",
        "passes_with_runtime_observable_failures",
        "passes_with_behavioral_false_positives",
        "behavioral_validation_missing_observations_by_pass",
        "passes_with_missing_affected_instruction_evidence",
        "platform_gap_scope",
        "corpus_gap_scope",
    ):
        value = summary.get(field)
        if field == "metric_missing_runs" and isinstance(value, dict):
            missing_metrics = {
                str(name): count for name, count in value.items() if isinstance(count, int) and count > 0
            }
            if missing_metrics:
                blockers[field] = missing_metrics
            continue
        if isinstance(value, dict):
            pending = {str(name): item for name, item in value.items() if item}
            if pending:
                blockers[field] = pending
            continue
        if isinstance(value, list) and value:
            blockers[field] = value
    return blockers


def _continuous_evidence_blocker_totals(blockers: Mapping[str, object]) -> dict[str, int]:
    totals = {field: len(value) for field, value in blockers.items() if isinstance(value, (list, dict))}
    totals["blocker_categories"] = len(blockers)
    totals["total_continuous_evidence_blockers"] = sum(
        count for field, count in totals.items() if field != "blocker_categories"
    )
    return dict(sorted(totals.items()))


def _metric_run_totals(summaries: dict[str, object], field_index: int) -> dict[str, int]:
    return {name: _sum_summary_field(summaries, fields[field_index]) for name, fields in _METRIC_RUN_FIELDS.items()}


def _passes_with_zero_runs(summaries: dict[str, object], field: str) -> list[str]:
    return sorted(name for name, summary in summaries.items() if isinstance(summary, dict) and summary.get(field) == 0)


def _passes_with_positive_runs(summaries: dict[str, object], field: str) -> list[str]:
    return sorted(
        name
        for name, summary in summaries.items()
        if isinstance(summary, dict) and isinstance(value := summary.get(field), int) and value > 0
    )


def _reason_map_by_pass(summaries: dict[str, object], field: str) -> dict[str, dict[str, int]]:
    return {
        name: dict(sorted(reasons.items()))
        for name, summary in summaries.items()
        if isinstance(summary, dict)
        and isinstance(reasons := summary.get(field), dict)
        and reasons
        and all(isinstance(reason, str) and isinstance(count, int) for reason, count in reasons.items())
    }


def _passes_with_incomplete_coverage(summaries: dict[str, object]) -> dict[str, list[str]]:
    incomplete: dict[str, list[str]] = {}
    for name, field in _COVERAGE_PERCENT_FIELDS.items():
        passes = _passes_below_full_coverage(summaries, field)
        if passes:
            incomplete[name] = passes
    return incomplete


def _passes_below_full_coverage(summaries: dict[str, object], field: str) -> list[str]:
    return sorted(
        name
        for name, summary in summaries.items()
        if isinstance(summary, dict)
        and isinstance(value := summary.get(field), int | float)
        and value < _FULL_COVERAGE_PERCENT
    )


def _complete_evidence_error(report: dict[str, object]) -> str | None:
    campaign_summary = report.get("campaign_summary")
    if isinstance(campaign_summary, Mapping):
        missing_runs = campaign_summary.get("total_complete_evidence_missing_runs")
        incomplete = campaign_summary.get("passes_with_incomplete_coverage")
        incomplete_passes = []
        if isinstance(incomplete, Mapping) and isinstance(value := incomplete.get("complete_evidence"), list):
            incomplete_passes = [str(name) for name in value]
        if missing_runs == 0 and not incomplete_passes:
            return None
        if incomplete_passes:
            return "incomplete complete-evidence coverage for passes: " + ", ".join(incomplete_passes)
        return "incomplete complete-evidence coverage"

    summary = report.get("summary")
    if isinstance(summary, Mapping):
        missing_runs = summary.get("complete_evidence_missing_runs")
        coverage = summary.get("complete_evidence_coverage_percent")
        if missing_runs == 0 and coverage == _FULL_COVERAGE_PERCENT:
            return None
        return f"incomplete complete-evidence coverage for {report.get('pass_name', 'selected pass')}"

    return "complete-evidence validation requires a maturity report summary"


def _select_fixtures(
    fixtures: list[Path],
    generated_corpus: bool,
    temp_dir: Path,
) -> tuple[list[Path], list[str], int, list[str]]:
    selected = list(fixtures)
    corpus_families = ["repository-fixtures"] if selected else []
    generated_fixture_count = 0
    generated_fixture_names: list[str] = []
    if generated_corpus:
        generated_fixtures = build_generated_corpus(temp_dir / "generated-corpus")
        generated_fixture_count = len(generated_fixtures)
        generated_fixture_names = sorted(path.name for path in generated_fixtures)
        selected.extend(generated_fixtures)
        corpus_families.append(_GENERATED_CORPUS_FAMILY)
        if any(name.startswith("generated_cpp_") for name in generated_fixture_names):
            corpus_families.append(_GENERATED_CPP_CORPUS_FAMILY)
    return selected, corpus_families, generated_fixture_count, generated_fixture_names


def _select_fixture_shard(fixtures: list[Path], index: int, count: int) -> list[Path]:
    """Select a deterministic corpus partition for parallel scheduled jobs."""
    if count < 1:
        raise ValueError("fixture shard count must be positive")
    if index < 0 or index >= count:
        raise ValueError("fixture shard index must be within the shard count")
    return fixtures[index::count]


def _campaign_fixture_selection(args: argparse.Namespace) -> tuple[list[Path], dict[str, int] | None]:
    if args.fixture_shard_count < 1:
        raise ValueError("--fixture-shard-count must be positive")
    if args.fixture_shard_index < 0 or args.fixture_shard_index >= args.fixture_shard_count:
        raise ValueError("--fixture-shard-index must be within --fixture-shard-count")
    if args.fixture_shard_count > 1 and not args.all_fixtures:
        raise ValueError("fixture sharding requires --all")
    fixtures = discover_executables(args.dataset) if args.all_fixtures else list(args.fixtures)
    if args.fixture_shard_count == 1:
        return fixtures, None
    return fixtures, {"index": args.fixture_shard_index, "count": args.fixture_shard_count}


def _apply_fixture_shard(fixtures: list[Path], fixture_shard: dict[str, int] | None) -> list[Path]:
    if fixture_shard is None:
        return fixtures
    return _select_fixture_shard(fixtures, fixture_shard["index"], fixture_shard["count"])


def _selected_generated_fixture_names(
    fixtures: list[Path], generated_fixture_names: list[str], fixture_shard: dict[str, int] | None
) -> tuple[list[str], int]:
    if fixture_shard is None:
        return generated_fixture_names, len(generated_fixture_names)
    selected_names = {path.name for path in fixtures}
    names = sorted(name for name in generated_fixture_names if name in selected_names)
    return names, len(names)


def _measure_campaign(
    fixtures: list[Path],
    pass_names: tuple[str, ...],
    args: argparse.Namespace,
    output_root: Path,
) -> dict[str, list[dict[str, object]]]:
    seeds = range(args.first_seed, args.first_seed + args.count)
    runtime_inputs = _GENERATED_RUNTIME_INPUTS if args.generated_inputs else _DEFAULT_RUNTIME_INPUTS
    return {
        pass_name: [measure_fixture(fixture, seeds, output_root, pass_name, runtime_inputs) for fixture in fixtures]
        for pass_name in pass_names
    }


def _emit_report(rendered: str, output: Path | None) -> None:
    if output:
        output.write_text(rendered)
        return
    print(rendered, end="")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixtures", nargs="*", type=Path)
    parser.add_argument("--all", action="store_true", dest="all_fixtures")
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--first-seed", type=int, default=20260820)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument(
        "--passes",
        default=DEFAULT_MUTATION_NAME,
        help="comma-separated pass names or 'all' (default: CodeVirtualization)",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-applied",
        action="store_true",
        help="fail when a selected pass does not apply; sharded campaigns defer this to aggregation",
    )
    parser.add_argument(
        "--require-complete-evidence",
        action="store_true",
        help="fail when runtime, size, duration, or static metric evidence is incomplete",
    )
    parser.add_argument(
        "--generated-inputs",
        action="store_true",
        help="compare default and generated argv runtime observables",
    )
    parser.add_argument(
        "--generated-corpus",
        action="store_true",
        help="compile synthetic Linux ELF x86-64 fixtures and include them in the corpus",
    )
    parser.add_argument(
        "--fixture-shard-index",
        type=int,
        default=0,
        help="zero-based corpus shard index for parallel campaigns",
    )
    parser.add_argument(
        "--fixture-shard-count",
        type=int,
        default=1,
        help="number of deterministic corpus shards for parallel campaigns",
    )
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    if args.all_fixtures and args.fixtures:
        parser.error("pass either --all or explicit fixture paths")
    try:
        fixtures, fixture_shard = _campaign_fixture_selection(args)
    except ValueError as error:
        parser.error(str(error))
    try:
        pass_names = _parse_pass_names(args.passes)
    except ValueError as error:
        parser.error(str(error))

    with tempfile.TemporaryDirectory(prefix="r2morph-maturity-") as temp_dir:
        try:
            fixtures, corpus_families, generated_fixture_count, generated_fixture_names = _select_fixtures(
                fixtures,
                args.generated_corpus,
                Path(temp_dir),
            )
        except RuntimeError as error:
            parser.error(str(error))
        if not fixtures:
            parser.error("no executable fixtures selected")
        fixtures = _apply_fixture_shard(fixtures, fixture_shard)
        generated_fixture_names, generated_fixture_count = _selected_generated_fixture_names(
            fixtures,
            generated_fixture_names,
            fixture_shard,
        )
        measurements = _measure_campaign(
            fixtures,
            pass_names,
            args,
            Path(temp_dir),
        )
    report = _render_result(measurements[pass_names[0]], pass_names[0])
    if len(pass_names) > 1:
        report = _render_multi_pass_result(
            measurements,
            args.dataset if args.all_fixtures else None,
            corpus_families,
            {
                "generated_fixture_count": generated_fixture_count,
                "generated_fixture_names": generated_fixture_names,
                "fixture_shard": fixture_shard,
            },
        )
    if args.require_applied and args.fixture_shard_count == 1:
        passes_without_mutations = [
            name
            for name, fixtures_for_pass in measurements.items()
            if _render_result(fixtures_for_pass, name)["summary"]["applied_runs"] == 0
        ]
        if passes_without_mutations:
            parser.error("selected passes did not apply to any fixture: " + ", ".join(passes_without_mutations))
    if args.require_complete_evidence and args.fixture_shard_count == 1 and (error := _complete_evidence_error(report)):
        parser.error(error)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    _emit_report(rendered, args.output)


if __name__ == "__main__":
    main()
