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
    __m128i shuffled = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    __m128i shuffle_mask = _mm_setzero_si128();
    __m128i right = _mm_set1_epi8(7);
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
        "pshufb %[shuffle_mask], %[shuffled]\n\t"
        "mov %[seed], %%rax\n\t"
        "movb (%[byte_source]), %%al\n\t"
        "movb %%al, (%[byte_destination])\n\t"
        "mov %%rax, %[byte_after]\n\t"
        "mov %[seed], %%rax\n\t"
        "movw (%[word_source]), %%ax\n\t"
        "movw %%ax, (%[word_destination])\n\t"
        "mov %%rax, %[word_after]\n\t"
        : [equal] "+x"(equal), [greater] "+x"(greater), [minimum] "+x"(minimum),
          [legacy_maximum] "+x"(legacy_maximum), [shift_left] "+x"(shift_left), [shift_right] "+x"(shift_right),
          [shift_arithmetic] "+x"(shift_arithmetic), [shuffled] "+x"(shuffled),
          [byte_after] "=m"(byte_after), [word_after] "=m"(word_after)
        : [right] "x"(right), [shuffle_mask] "x"(shuffle_mask),
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
        && _mm_movemask_epi8(shuffled) == 0
        && byte_after == 0x11223344556677a5ULL
        && word_after == 0x1122334455661234ULL
        && byte_roundtrip == byte_value
        && word_roundtrip == word_value
        ? 46
        : 1;
}

__attribute__((noinline)) static int packed_minimums(void) {
    __m128i signed_min = _mm_set1_epi16(300);
    __m128i signed_max = _mm_set1_epi16(300);
    __m128i signed_other = _mm_set1_epi16(-400);
    __m128i unsigned_min = _mm_set1_epi16(300);
    __m128i unsigned_max = _mm_set1_epi16(300);
    __m128i unsigned_other = _mm_set1_epi16(50000);
    __m128i madd = _mm_set1_epi8(2);
    __m128i madd_other = _mm_set1_epi8(3);
    short signed_min_result[8];
    short signed_max_result[8];
    unsigned short unsigned_min_result[8];
    unsigned short unsigned_max_result[8];
    unsigned short madd_result[8];
    __asm__ volatile(
        "pminsw %[signed_other], %[signed_min]\n\t"
        "pmaxsw %[signed_other], %[signed_max]\n\t"
        "pminuw %[unsigned_other], %[unsigned_min]\n\t"
        "pmaxuw %[unsigned_other], %[unsigned_max]\n\t"
        "pmaddubsw %[madd_other], %[madd]\n\t"
        : [signed_min] "+x"(signed_min), [signed_max] "+x"(signed_max), [unsigned_min] "+x"(unsigned_min),
          [unsigned_max] "+x"(unsigned_max), [madd] "+x"(madd)
        : [signed_other] "x"(signed_other), [unsigned_other] "x"(unsigned_other), [madd_other] "x"(madd_other)
    );
    _mm_storeu_si128((__m128i *)signed_min_result, signed_min);
    _mm_storeu_si128((__m128i *)signed_max_result, signed_max);
    _mm_storeu_si128((__m128i *)unsigned_min_result, unsigned_min);
    _mm_storeu_si128((__m128i *)unsigned_max_result, unsigned_max);
    _mm_storeu_si128((__m128i *)madd_result, madd);
    return signed_min_result[0] == -400
        && signed_max_result[0] == 300
        && unsigned_min_result[0] == 300
        && unsigned_max_result[0] == 50000
        && madd_result[0] == 12
        ? 0
        : 1;
}

__attribute__((noinline)) static int packed_immediate_shift(void) {
    __m128i immediate_shift = _mm_set1_epi32(1);
    __m128i expected_immediate_shift = _mm_set1_epi32(32);
    __asm__ volatile("pslld $5, %[immediate_shift]\n\t" : [immediate_shift] "+x"(immediate_shift));
    return _mm_movemask_epi8(_mm_cmpeq_epi32(immediate_shift, expected_immediate_shift)) == 0xffff ? 0 : 1;
}

int main(void) {
    return packed_operations() + packed_minimums() + packed_immediate_shift();
}
""",
    )
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-mavx",
            "-mssse3",
            "-msse4.1",
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


def test_virtualized_elf_preserves_legacy_packed_word_comparisons(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native packed word comparison execution requires an x86-64 host")
    source = tmp_path / "packed_word_compare.c"
    executable = tmp_path / "packed_word_compare"
    source.write_text(
        r"""
#include <immintrin.h>

__attribute__((noinline)) static int packed_word_comparisons(void) {
    __m128i equal = _mm_set1_epi16(7);
    __m128i greater = _mm_set1_epi16(6);
    __m128i source = _mm_set1_epi16(7);
    __asm__ volatile(
        "pcmpeqw %[source], %[equal]\n\t"
        "pcmpgtw %[source], %[greater]\n\t"
        : [equal] "+x"(equal), [greater] "+x"(greater)
        : [source] "x"(source)
    );
    return _mm_movemask_epi8(equal) == 0xffff && _mm_movemask_epi8(greater) == 0 ? 42 : 1;
}

int main(void) {
    return packed_word_comparisons();
}
""",
    )
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-mavx",
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
    expect(compile_result.returncode == 0, "failed to compile the packed word comparison fixture")

    original_result = run_command([executable], timeout=30)
    with Binary(executable, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260908}).apply(binary)
        binary.save()

    mutated_result = run_command([executable], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"packed word comparison fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (42, 42),
        f"packed word comparison result changed: original={original_result.returncode}, "
        f"mutated={mutated_result.returncode}",
    )


def test_virtualized_vex_packed_even_dword_multiply_preserves_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native VEX packed multiplication requires an x86-64 host")
    source = tmp_path / "vex_pmulldq.c"
    executable = tmp_path / "vex_pmulldq"
    source.write_text(
        r"""
#include <immintrin.h>

__attribute__((noinline)) static int packed_multiply(void) {
    __m128i left = _mm_set_epi32(4, 3, 2, 1);
    __m128i right = _mm_set_epi32(8, 7, 6, 5);
    __m128i result;
    unsigned long long products[2];
    __asm__ volatile("vpmuldq %[left], %[right], %[result]\n\t"
                     : [result] "=&x"(result)
                     : [left] "x"(left), [right] "x"(right));
    _mm_storeu_si128((__m128i *)products, result);
    return products[0] == 5 && products[1] == 21 ? 42 : 1;
}

int main(void) {
    return packed_multiply();
}
""",
    )
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-mavx2",
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
    expect(compile_result.returncode == 0, "failed to compile the VEX packed multiply fixture")

    original_result = run_command([executable], timeout=30)
    with Binary(executable, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260910}).apply(binary)
        binary.save()

    mutated_result = run_command([executable], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"VEX packed multiply fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (42, 42),
        f"VEX packed multiply result changed: original={original_result.returncode}, "
        f"mutated={mutated_result.returncode}",
    )


def test_virtualized_vex_packed_unsigned_even_dword_multiply_preserves_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native VEX packed multiplication requires an x86-64 host")
    source = tmp_path / "vex_pmuludq.c"
    executable = tmp_path / "vex_pmuludq"
    source.write_text(
        r"""
#include <immintrin.h>

__attribute__((noinline)) static int packed_unsigned_multiply(void) {
    __m128i left = _mm_set_epi32(0, 0x80000000, 0, 0xffffffff);
    __m128i right = _mm_set_epi32(0, 2, 0, 2);
    __m128i result;
    unsigned long long products[2];
    __asm__ volatile("vpmuludq %[left], %[right], %[result]\n\t"
                     : [result] "=&x"(result)
                     : [left] "x"(left), [right] "x"(right));
    _mm_storeu_si128((__m128i *)products, result);
    return products[0] == 0x1fffffffeULL && products[1] == 0x100000000ULL ? 42 : 1;
}

int main(void) {
    return packed_unsigned_multiply();
}
""",
    )
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-mavx2",
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
    expect(compile_result.returncode == 0, "failed to compile the unsigned VEX packed multiply fixture")

    original_result = run_command([executable], timeout=30)
    with Binary(executable, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260911}).apply(binary)
        binary.save()

    mutated_result = run_command([executable], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"unsigned VEX packed multiply fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (42, 42),
        f"unsigned VEX packed multiply result changed: original={original_result.returncode}, "
        f"mutated={mutated_result.returncode}",
    )


def test_virtualized_vex128_variable_shift_and_addsub_preserve_result(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native VEX.128 SIMD execution requires an x86-64 host")
    source = tmp_path / "vex128_shift_addsub.c"
    executable = tmp_path / "vex128_shift_addsub"
    source.write_text(
        r"""
#include <immintrin.h>
#include <stdint.h>

__attribute__((noinline)) static int vex128_operations(void) {
    __m128i values = _mm_set_epi32(4, 3, 2, 1);
    __m128i counts = _mm_set1_epi32(1);
    __m128i shifted;
    float left_values[4] = {10.0f, 20.0f, 30.0f, 40.0f};
    float right_values[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    uint32_t shifted_values[4];
    float result_values[4];
    __m128 left = _mm_loadu_ps(left_values);
    __m128 right = _mm_loadu_ps(right_values);
    __m128 result;
    __asm__ volatile(
        "vpsllvd %[counts], %[values], %[shifted]\n\t"
        "vaddsubps %[right], %[left], %[result]\n\t"
        : [shifted] "=&x"(shifted), [result] "=&x"(result)
        : [values] "x"(values), [counts] "x"(counts), [left] "x"(left), [right] "x"(right));
    _mm_storeu_si128((__m128i *)shifted_values, shifted);
    _mm_storeu_ps(result_values, result);
    return shifted_values[0] == 2
        && shifted_values[3] == 8
        && result_values[0] == 9.0f
        && result_values[1] == 22.0f
        && result_values[2] == 27.0f
        && result_values[3] == 44.0f
        ? 42
        : 1;
}

int main(void) {
    return vex128_operations();
}
""",
    )
    compile_result = run_command(
        [
            "gcc",
            "-O0",
            "-mavx2",
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
    expect(compile_result.returncode == 0, "failed to compile the VEX.128 shift/addsub fixture")
    original_result = run_command([executable], timeout=30)
    with Binary(executable, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260912}).apply(binary)
        binary.save()
    mutated_result = run_command([executable], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"VEX.128 shift/addsub fixture was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (42, 42),
        f"VEX.128 shift/addsub result changed: original={original_result.returncode}, "
        f"mutated={mutated_result.returncode}",
    )
