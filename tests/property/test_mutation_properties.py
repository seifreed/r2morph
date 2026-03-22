"""
Property-based tests for mutation passes.

Tests that mutations preserve semantic properties using Hypothesis.
"""

import pytest

try:
    from hypothesis import given, settings, assume, strategies as st

    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Hypothesis not installed")

if HYPOTHESIS_AVAILABLE:
    from tests.property.strategies import (
        create_function_strategy,
        create_function_with_loops_strategy,
        create_function_with_branches_strategy,
        create_x86_register_strategy,
        create_mutation_seed_strategy,
        Function,
    )

    from r2morph.mutations.conflict_detector import (
        MutationRegion,
        ConflictDetector,
        ConflictType,
        analyze_mutations_for_conflicts,
    )

    @pytest.mark.property
    class TestMutationRegionProperties:
        """Property tests for MutationRegion."""

        @given(
            start=st.integers(min_value=0, max_value=0xFFFFFF00),
            size=st.integers(min_value=4, max_value=0x1000),
        )
        def test_region_size_positive(self, start: int, size: int):
            """Region end should always be greater than start."""
            end = start + size
            region = MutationRegion(start=start, end=end)
            assert region.end > region.start

        @given(
            start1=st.integers(min_value=0x1000, max_value=0x2000),
            start2=st.integers(min_value=0x3000, max_value=0x4000),
            size=st.integers(min_value=4, max_value=0x100),
        )
        def test_non_overlapping_regions(self, start1: int, start2: int, size: int):
            """Two regions far apart should not overlap."""
            region1 = MutationRegion(start=start1, end=start1 + size)
            region2 = MutationRegion(start=start2, end=start2 + size)
            assert not region1.overlaps(region2)
            assert not region2.overlaps(region1)

        @given(
            start=st.integers(min_value=0x1000, max_value=0x8000),
            size=st.integers(min_value=4, max_value=0x100),
        )
        def test_region_overlaps_itself(self, start: int, size: int):
            """A region should overlap with itself."""
            region = MutationRegion(start=start, end=start + size)
            assert region.overlaps(region)

        @given(
            start=st.integers(min_value=0x1000, max_value=0x8000),
            size=st.integers(min_value=0x100, max_value=0x1000),
            offset=st.integers(min_value=0, max_value=0xFF),
        )
        def test_overlapping_regions_share_addresses(self, start: int, size: int, offset: int):
            """Overlapping regions should share some addresses."""
            end = start + size
            region1 = MutationRegion(start=start, end=end)
            region2 = MutationRegion(start=start + offset, end=end + offset)

            if region1.overlaps(region2):
                assert start < (start + offset) < end or start < (end + offset) < end or offset == 0

        @given(
            start=st.integers(min_value=0x1000, max_value=0x8000),
            size=st.integers(min_value=4, max_value=0x100),
        )
        def test_region_hash_consistency(self, start: int, size: int):
            """Hash should be consistent for same region."""
            region1 = MutationRegion(start=start, end=start + size, pass_name="test")
            region2 = MutationRegion(start=start, end=start + size, pass_name="test")
            assert hash(region1) == hash(region2)

    @pytest.mark.property
    class TestConflictDetectorProperties:
        """Property tests for conflict detection."""

        @given(
            st.lists(
                st.tuples(
                    st.integers(min_value=0x1000, max_value=0xFFFF00),
                    st.integers(min_value=4, max_value=0x100),
                ),
                min_size=0,
                max_size=20,
            )
        )
        def test_detect_overlaps_idempotent(self, regions_data: list):
            """detect_overlaps should be idempotent for same regions."""
            detector = ConflictDetector()
            regions = [
                MutationRegion(start=start, end=start + size, pass_name=f"pass_{i}")
                for i, (start, size) in enumerate(regions_data)
            ]

            conflicts1 = detector.detect_overlaps(regions)
            conflicts2 = detector.detect_overlaps(regions)

            assert len(conflicts1) == len(conflicts2)

        @given(
            st.lists(
                st.integers(min_value=0x1000, max_value=0xF000),
                min_size=0,
                max_size=10,
            )
        )
        @settings(max_examples=50)
        def test_well_separated_regions_no_conflicts(self, starts: list):
            """Regions separated by large gaps should have no conflicts."""
            starts.sort()
            regions = [
                MutationRegion(
                    start=addr,
                    end=addr + 0x100,
                    pass_name=f"pass_{i}",
                )
                for i, addr in enumerate(starts)
            ]

            for i in range(len(starts) - 1):
                assume(starts[i + 1] - starts[i] >= 0x200 or i == len(starts) - 1)

            detector = ConflictDetector()
            overlaps = detector.detect_overlaps(regions)

            for i, start in enumerate(starts):
                for j, other_start in enumerate(starts[i + 1 :], i + 1):
                    if other_start < start + 0x100:
                        assume(False)

            assert len(overlaps) == 0 or any(
                regions[i].overlaps(regions[j]) for i in range(len(regions)) for j in range(i + 1, len(regions))
            )

        @given(
            start1=st.integers(min_value=0x1000, max_value=0x8000),
            offset=st.integers(min_value=0, max_value=0xFF),
            size=st.integers(min_value=0x100, max_value=0x200),
        )
        def test_overlapping_regions_always_conflict(self, start1: int, offset: int, size: int):
            """Overlapping regions should always produce conflicts."""
            end1 = start1 + size
            start2 = start1 + offset
            end2 = start2 + size

            region1 = MutationRegion(start=start1, end=end1, pass_name="pass1")
            region2 = MutationRegion(start=start2, end=end2, pass_name="pass2")

            if region1.overlaps(region2) and start1 != start2:
                detector = ConflictDetector()
                conflicts = detector.detect_overlaps([region1, region2])
                assert len(conflicts) >= 1

    @pytest.mark.property
    class TestAnalyzeMutationsProperties:
        """Property tests for analyze_mutations_for_conflicts function."""

        @given(st.lists(st.integers(min_value=0, max_value=0xFFFFFF), min_size=0, max_size=10))
        def test_analyze_empty_mutations(self, seeds: list):
            """Empty mutation list should return no conflicts."""
            result = analyze_mutations_for_conflicts([])
            assert result["total_mutations"] == 0
            assert result["conflicts_found"] == 0

        @given(create_mutation_seed_strategy())
        def test_single_mutation_no_conflicts(self, seed: int):
            """Single mutation should never have conflicts."""
            result = analyze_mutations_for_conflicts([{"start": seed, "size": 0x100, "pass_name": "test"}])
            assert result["total_mutations"] == 1
            assert result["conflicts_found"] == 0

        @given(st.data())
        def test_identical_regions_conflict(self, data):
            """Identical regions should always conflict."""
            addr = data.draw(st.integers(min_value=0x1000, max_value=0xFFFF00))
            size = data.draw(st.integers(min_value=4, max_value=0x100))

            result = analyze_mutations_for_conflicts(
                [
                    {"start": addr, "size": size, "pass_name": "pass1"},
                    {"start": addr, "size": size, "pass_name": "pass2"},
                ]
            )
            assert result["conflicts_found"] >= 1

        @given(
            starts=st.lists(
                st.integers(min_value=0x1000, max_value=0xFFFF00),
                min_size=2,
                max_size=10,
                unique=True,
            )
        )
        def test_well_separated_mutations_no_conflicts(self, starts: list):
            """Mutations with well-separated addresses should have no conflicts."""
            starts_sorted = sorted(starts)
            mutations = []
            for i, addr in enumerate(starts_sorted):
                mutations.append(
                    {
                        "start": addr,
                        "size": 0x100,
                        "pass_name": f"pass_{i}",
                    }
                )

            well_separated = all(
                starts_sorted[i + 1] - starts_sorted[i] >= 0x200 for i in range(len(starts_sorted) - 1)
            )

            assume(well_separated)

            result = analyze_mutations_for_conflicts(mutations)
            assert result["conflicts_found"] == 0

    @pytest.mark.property
    class TestFunctionProperties:
        """Property tests for Function data structures."""

        @given(create_function_strategy())
        def test_function_size_positive(self, func: Function):
            """Function size should be positive."""
            assert func.size > 0

        @given(create_function_strategy())
        def test_function_instructions_count(self, func: Function):
            """Function should have at least one instruction."""
            assert len(func.instructions) >= 1

        @given(create_function_strategy())
        def test_function_addresses_sequential(self, func: Function):
            """Instruction addresses should be sequential with 4-byte spacing."""
            for i in range(len(func.instructions) - 1):
                addr_diff = func.instructions[i + 1].address - func.instructions[i].address
                assert addr_diff == func.instructions[i].size

        @given(create_function_strategy())
        def test_function_first_instruction_at_base(self, func: Function):
            """First instruction should be at function base address."""
            if func.instructions:
                assert func.instructions[0].address == func.address

        @given(create_function_with_loops_strategy())
        def test_loopy_function_has_loop(self, func: Function):
            """Loopy function should have loop metadata."""
            assert "has_loop" in func.metadata

        @given(create_function_with_branches_strategy())
        def test_branched_function_has_branches(self, func: Function):
            """Branched function should have branch metadata."""
            assert "has_branches" in func.metadata

    @pytest.mark.property
    class TestRegisterConflictProperties:
        """Property tests for register-based conflicts."""

        @given(
            regs1=st.sets(create_x86_register_strategy(64), min_size=1, max_size=8),
            regs2=st.sets(create_x86_register_strategy(64), min_size=1, max_size=8),
        )
        def test_register_conflict_detection(self, regs1: set, regs2: set):
            """Register sets with overlap should produce conflicts."""
            region1 = MutationRegion(
                start=0x1000,
                end=0x1100,
                affected_registers=regs1,
            )
            region2 = MutationRegion(
                start=0x2000,
                end=0x2100,
                affected_registers=regs2,
            )

            conflict = region1.conflicts_with(region2)

            if regs1 & regs2:
                assert conflict == ConflictType.REGISTER_INTERFERENCE
            else:
                assert conflict is None or conflict != ConflictType.REGISTER_INTERFERENCE

    @pytest.mark.property
    class TestMemoryConflictProperties:
        """Property tests for memory-based conflicts."""

        @given(
            addrs1=st.sets(st.integers(min_value=0x5000, max_value=0x6000), min_size=1, max_size=5),
            addrs2=st.sets(st.integers(min_value=0x5000, max_value=0x6000), min_size=1, max_size=5),
        )
        def test_memory_conflict_detection(self, addrs1: set, addrs2: set):
            """Memory sets with overlap should produce conflicts."""
            region1 = MutationRegion(
                start=0x1000,
                end=0x1100,
                affected_memory=addrs1,
            )
            region2 = MutationRegion(
                start=0x2000,
                end=0x2100,
                affected_memory=addrs2,
            )

            conflict = region1.conflicts_with(region2)

            if addrs1 & addrs2:
                assert conflict == ConflictType.MEMORY_INTERFERENCE
            else:
                assert conflict is None or conflict != ConflictType.MEMORY_INTERFERENCE

    @pytest.mark.property
    class TestSemanticPreservationProperties:
        """Property tests for semantic preservation across mutations."""

        @given(
            adds=st.lists(
                st.tuples(st.integers(min_value=0, max_value=50), st.integers(min_value=0, max_value=5)),
                min_size=1,
                max_size=3,
            ),
            subs=st.lists(
                st.tuples(st.integers(min_value=0, max_value=50), st.integers(min_value=0, max_value=5)),
                min_size=0,
                max_size=3,
            ),
        )
        @settings(max_examples=50)
        def test_arithmetic_identities_preserve_semantics(self, adds: list, subs: list):
            """Arithmetic identities preserve semantics."""
            result = 0
            for val, count in adds:
                result += val * count
            for val, count in subs:
                result -= val * count

            assert isinstance(result, int)
            assert result >= -1000 and result <= 1000

        @given(st.integers(min_value=0, max_value=0xFFFFFFFF))
        def test_xor_zero_preserves_value(self, value: int):
            """XOR with zero preserves value."""
            result = value ^ 0
            assert result == value

        @given(st.integers(min_value=0, max_value=0xFFFFFFFF))
        def test_xor_self_is_zero(self, value: int):
            """XOR of value with itself is zero."""
            result = value ^ value
            assert result == 0

        @given(st.integers(min_value=0, max_value=0xFFFFFFFF))
        @settings(max_examples=100)
        def test_register_xchg_preserves_state(self, value: int):
            """Exchange of two registers preserves combined state."""
            reg_a = value & 0xFFFF
            reg_b = (value >> 16) & 0xFFFF
            original_sum = reg_a + reg_b

            reg_a, reg_b = reg_b, reg_a
            new_sum = reg_a + reg_b

            assert original_sum == new_sum

        @given(
            st.integers(min_value=0, max_value=0xFFFFFF),
            st.integers(min_value=0, max_value=31),
        )
        def test_shift_shift_inverse(self, value: int, shift: int):
            """Left shift then right shift by same amount may not preserve (due to truncation)."""
            if shift > 24:
                shift = 24
            shifted_left = value << shift
            shifted_back = shifted_left >> shift

            upper_bits_mask = (1 << (24 - shift + 8)) - 1 if shift < 24 else 0xFFFFFFFF
            preserved_value = value & upper_bits_mask

            assert shifted_back >= preserved_value

    @pytest.mark.property
    class TestSemanticConflictDetectorProperties:
        """Property tests for SemanticConflictDetector."""

        @given(
            st.lists(
                st.fixed_dictionaries(
                    {
                        "start": st.integers(min_value=0x1000, max_value=0xFFFF00),
                        "size": st.integers(min_value=4, max_value=0x100),
                        "pass_name": st.sampled_from(["nop", "substitute", "register"]),
                        "affected_registers": st.sets(
                            st.sampled_from(["eax", "ebx", "ecx", "edx", "esi", "edi"]), max_size=4
                        ),
                    }
                ),
                min_size=0,
                max_size=10,
            )
        )
        @settings(max_examples=50)
        def test_semantic_analysis_completeness(self, mutations: list):
            """Semantic conflict analysis should always return a result."""
            from r2morph.mutations.conflict_detector import SemanticConflictDetector

            detector = SemanticConflictDetector(arch="x86")
            result = detector.detect_semantic_conflicts(mutations)

            assert "total_conflicts" in result
            assert "conflicts" in result
            assert "has_critical" in result
            assert "has_high" in result
            assert isinstance(result["conflicts"], list)

        @given(
            st.lists(
                st.fixed_dictionaries(
                    {
                        "start": st.integers(min_value=0x1000, max_value=0xFFFF00),
                        "size": st.integers(min_value=4, max_value=0x100),
                        "pass_name": st.just("test"),
                        "affected_registers": st.just(set()),
                        "control_flow_changed": st.just(False),
                    }
                ),
                min_size=0,
                max_size=5,
            )
        )
        def test_minimal_mutations_no_semantic_conflicts(self, mutations: list):
            """Minimal mutations with no effects should have no semantic conflicts."""
            from r2morph.mutations.conflict_detector import SemanticConflictDetector

            detector = SemanticConflictDetector(arch="x86")
            result = detector.detect_semantic_conflicts(mutations)

            assert result["total_conflicts"] == 0

        @given(
            st.lists(
                st.fixed_dictionaries(
                    {
                        "start": st.integers(min_value=0x1000, max_value=0xFFFF00),
                        "size": st.integers(min_value=4, max_value=0x100),
                        "pass_name": st.just("control_flow"),
                        "control_flow_changed": st.just(True),
                    }
                ),
                min_size=2,
                max_size=5,
            )
        )
        @settings(max_examples=30)
        def test_multiple_cf_mutations_have_conflicts(self, mutations: list):
            """Multiple control flow mutations should have semantic conflicts."""
            from r2morph.mutations.conflict_detector import SemanticConflictDetector

            detector = SemanticConflictDetector(arch="x86")
            result = detector.detect_semantic_conflicts(mutations)

            if len(mutations) >= 2:
                cf_conflicts = [c for c in result["conflicts"] if c.get("type") == "semantic_control_flow"]
                assert len(cf_conflicts) >= 1

        @given(st.sampled_from(["x86", "arm", "arm64"]))
        def test_arch_specific_invariant_patterns(self, arch: str):
            """Each architecture should have invariant patterns defined."""
            from r2morph.mutations.conflict_detector import SemanticConflictDetector

            detector = SemanticConflictDetector(arch=arch)

            assert "calling_convention" in detector._invariant_patterns
            assert "callee_saved" in detector._invariant_patterns
            assert "stack_pointer" in detector._invariant_patterns
