"""
Real integration tests for detection modules.
"""

import importlib.util
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph import MorphEngine
from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult
from r2morph.detection.evasion_scorer import EvasionScore, EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from r2morph.mutations import NopInsertionPass

_EXPECTED_0_100 = 100
_EXPECTED_0_100_2 = 100
_EXPECTED_0_100_3 = 100
_EXPECTED_0_100_4 = 100
_EXPECTED_0_100_5 = 100
_EXPECTED_0_8_0 = 8.0
_EXPECTED_0_8_0_2 = 8.0
_EXPECTED_ABS_TOTAL_WEIGHT_1_0_0_01 = 0.01
_EXPECTED_ANALYZER_HIGH_ENTROPY_THRESHOLD_7_0 = 7.0
_EXPECTED_ANALYZER_SUSPICIOUS_ENTROPY_THRESHOLD_6_5 = 6.5


class TestEntropyAnalyzer:
    """Tests for EntropyAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    @pytest.fixture
    def pe_x86_64_exe(self):
        """Path to pe_x86_64.exe PE binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "pe_x86_64.exe"

    def test_analyze_file_elf(self, ls_elf):
        """Test entropy analysis on ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        expect(isinstance(result, EntropyResult))
        expect(0 <= result.overall_entropy <= _EXPECTED_0_8_0)
        expect(isinstance(result.section_entropies, dict))
        expect(isinstance(result.suspicious_sections, list))
        expect(isinstance(result.is_packed, bool))
        expect(isinstance(result.analysis, str))

    def test_analyze_file_pe(self, pe_x86_64_exe):
        """Test entropy analysis on PE binary."""
        if not pe_x86_64_exe.exists():
            pytest.skip("PE binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(pe_x86_64_exe)

        expect(isinstance(result, EntropyResult))
        expect(0 <= result.overall_entropy <= _EXPECTED_0_8_0_2)
        expect(isinstance(result.is_packed, bool))

    def test_entropy_result_str(self, ls_elf):
        """Test EntropyResult string representation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        result_str = str(result)
        expect(not ("Entropy Analysis" not in result_str))
        expect(not ("Overall:" not in result_str))

    def test_entropy_thresholds(self, ls_elf):
        """Test entropy threshold detection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        expect(analyzer.HIGH_ENTROPY_THRESHOLD == _EXPECTED_ANALYZER_HIGH_ENTROPY_THRESHOLD_7_0)
        expect(analyzer.SUSPICIOUS_ENTROPY_THRESHOLD == _EXPECTED_ANALYZER_SUSPICIOUS_ENTROPY_THRESHOLD_6_5)

    def test_suspicious_sections(self, pe_x86_64_exe):
        """Test detection of suspicious high-entropy sections."""
        if not pe_x86_64_exe.exists():
            pytest.skip("PE binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(pe_x86_64_exe)

        expect(isinstance(result.suspicious_sections, list))
        for section in result.suspicious_sections:
            expect(isinstance(section, str))


class TestEvasionScorer:
    """Tests for EvasionScorer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_score_mutations(self, ls_elf, tmp_path):
        """Test evasion scoring on mutated binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_morphed"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass(config={"probability": 0.5}))
            engine.run()
            engine.save(morphed_path)

        scorer = EvasionScorer()
        result = scorer.score(ls_elf, morphed_path)

        expect(isinstance(result, EvasionScore))
        expect(0 <= result.overall_score <= _EXPECTED_0_100)
        expect(0 <= result.hash_change_score <= _EXPECTED_0_100_2)
        expect(0 <= result.entropy_score <= _EXPECTED_0_100_3)
        expect(0 <= result.structure_score <= _EXPECTED_0_100_4)
        expect(0 <= result.signature_score <= _EXPECTED_0_100_5)
        expect(isinstance(result.details, dict))

    def test_evasion_score_str(self, ls_elf, tmp_path):
        """Test EvasionScore string representation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_morphed2"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        scorer = EvasionScorer()
        result = scorer.score(ls_elf, morphed_path)

        result_str = str(result)
        expect(not ("Evasion Score:" not in result_str))
        expect(not ("Hash Change:" not in result_str))
        expect(not ("Entropy:" not in result_str))

    def test_scorer_weights(self):
        """Test evasion scorer weights."""
        scorer = EvasionScorer()

        expect(not ("hash_change" not in scorer.weights))
        expect(not ("entropy" not in scorer.weights))
        expect(not ("structure" not in scorer.weights))
        expect(not ("signature" not in scorer.weights))

        total_weight = sum(scorer.weights.values())
        expect(not (abs(total_weight - 1.0) >= _EXPECTED_ABS_TOTAL_WEIGHT_1_0_0_01))

    def test_hash_change_detection(self, ls_elf, tmp_path):
        """Test hash change detection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_hash_test"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass(config={"probability": 0.9}))
            engine.run()
            engine.save(morphed_path)

        scorer = EvasionScorer()
        result = scorer.score(ls_elf, morphed_path)

        expect(result.details.get("hash_changed") is not None)


class TestSimilarityHasher:
    """Tests for SimilarityHasher."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_hasher_initialization(self):
        """Test SimilarityHasher initialization."""
        hasher = SimilarityHasher()

        expect(isinstance(hasher.has_ssdeep, bool))
        expect(isinstance(hasher.has_tlsh, bool))

    def test_hash_file(self, ls_elf):
        """Test file hashing."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        result = hasher.hash_file(ls_elf)

        expect(isinstance(result, dict))
        expect(not ("ssdeep" not in result))
        expect(not ("tlsh" not in result))

    def test_compare_hashes(self, ls_elf, tmp_path):
        """Test comparing hashes of original and morphed binaries."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_similarity"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        hasher = SimilarityHasher()
        original_hashes = hasher.hash_file(ls_elf)
        morphed_hashes = hasher.hash_file(morphed_path)

        expect(isinstance(original_hashes, dict))
        expect(isinstance(morphed_hashes, dict))

    def test_tool_check(self):
        """Test tool availability check."""
        hasher = SimilarityHasher()

        result = hasher._check_tool("ls")
        expect(isinstance(result, bool))
