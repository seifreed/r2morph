"""Real ELF regression coverage for additional packed integer SIMD operations."""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

_EXPECTED_EXIT_CODE = 46


def test_virtualized_elf_preserves_additional_packed_integer_operations(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("the packed integer SIMD regression is x86-64 specific")
    source = tmp_path / "packed_extra.c"
    executable = tmp_path / "packed_extra"
    source.write_text(
        r"""
#include <immintrin.h>

__attribute__((noinline)) static int packed_operations(void) {
    unsigned char byte_value = 0xa5;
    unsigned short word_value = 0x1234;
    unsigned long long byte_after = 0;
    unsigned long long word_after = 0;
    unsigned char byte_roundtrip = 0;
    unsigned short word_roundtrip = 0;
    unsigned long long seed = 0x1122334455667788ULL;
    __m128i equal = _mm_set1_epi8(7);
    __m128i greater = _mm_set1_epi8(7);
    __m128i minimum = _mm_set1_epi8(-1);
    __m128i maximum = _mm_set1_epi8(0);
    __m128i shuffled = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    __m128i shuffle_mask = _mm_setzero_si128();
    __m128i right = _mm_set1_epi8(7);
    __m128i vex_right = _mm_set1_epi8(-1);
    __m128i shift_left = _mm_set1_epi16(0x0011);
    __m128i shift_right = _mm_set1_epi16(0x0044);
    __m128i shift_arithmetic = _mm_set1_epi16(-16);
    __m128i shift_count = _mm_cvtsi64_si128(1);
    __m128i legacy_maximum = _mm_setzero_si128();
    __asm__ volatile(
        "pcmpeqb %[right], %[equal]\n\t"
        "pcmpgtb %[right], %[greater]\n\t"
        "pminub %[right], %[minimum]\n\t"
        "pmaxub %[right], %[legacy_maximum]\n\t"
        "psllw %[shift_count], %[shift_left]\n\t"
        "psrlw %[shift_count], %[shift_right]\n\t"
        "psraw %[shift_count], %[shift_arithmetic]\n\t"
        "vpmaxub %[vex_right], %[vex_right], %[maximum]\n\t"
        "pshufb %[shuffle_mask], %[shuffled]\n\t"
        "mov %[seed], %%rax\n\t"
        "movb (%[byte_source]), %%al\n\t"
        "movb %%al, (%[byte_destination])\n\t"
        "mov %%rax, %[byte_after]\n\t"
        "mov %[seed], %%rax\n\t"
        "movw (%[word_source]), %%ax\n\t"
        "movw %%ax, (%[word_destination])\n\t"
        "mov %%rax, %[word_after]\n\t"
        : [equal] "+x"(equal), [greater] "+x"(greater), [minimum] "+x"(minimum), [maximum] "+&x"(maximum),
          [legacy_maximum] "+x"(legacy_maximum), [shift_left] "+x"(shift_left), [shift_right] "+x"(shift_right),
          [shift_arithmetic] "+x"(shift_arithmetic), [shuffled] "+x"(shuffled),
          [byte_after] "=m"(byte_after), [word_after] "=m"(word_after)
        : [right] "x"(right), [vex_right] "x"(vex_right), [shuffle_mask] "x"(shuffle_mask),
          [shift_count] "x"(shift_count), [seed] "m"(seed),
          [byte_source] "r"(&byte_value), [word_source] "r"(&word_value),
          [byte_destination] "r"(&byte_roundtrip), [word_destination] "r"(&word_roundtrip)
        : "rax", "memory"
    );
    return _mm_movemask_epi8(equal) == 0xffff
        && _mm_movemask_epi8(greater) == 0
        && _mm_movemask_epi8(minimum) == 0
        && _mm_movemask_epi8(legacy_maximum) == 0
        && _mm_movemask_epi8(shift_left) == 0
        && _mm_movemask_epi8(shift_right) == 0
        && _mm_movemask_epi8(shift_arithmetic) == 0xffff
        && _mm_movemask_epi8(maximum) == 0xffff
        && _mm_movemask_epi8(shuffled) == 0
        && byte_after == 0x11223344556677a5ULL
        && word_after == 0x1122334455661234ULL
        && byte_roundtrip == byte_value
        && word_roundtrip == word_value
        ? 46
        : 1;
}

__attribute__((noinline)) static int packed_immediate_shift(void) {
    __m128i immediate_shift = _mm_set1_epi32(1);
    __m128i expected_immediate_shift = _mm_set1_epi32(32);
    __asm__ volatile("pslld $5, %[immediate_shift]\n\t" : [immediate_shift] "+x"(immediate_shift));
    return _mm_movemask_epi8(_mm_cmpeq_epi32(immediate_shift, expected_immediate_shift)) == 0xffff ? 0 : 1;
}

int main(void) {
    return packed_operations() + packed_immediate_shift();
}
""",
    )
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-mavx",
            "-mssse3",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            "-fcf-protection=none",
            source,
            "-o",
            executable,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile the packed SIMD fixture")

    original_result = run_command([executable], timeout=30)
    with Binary(executable, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260908}).apply(binary)
        binary.save()

    mutated_result = run_command([executable], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"packed SIMD fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE),
        f"packed SIMD result changed: original={original_result.returncode}, mutated={mutated_result.returncode}",
    )
