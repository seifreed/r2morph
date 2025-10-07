"""
Real integration tests for detection modules.
"""

from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult
from r2morph.detection.evasion_scorer import EvasionScore, EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from r2morph.mutations import NopInsertionPass


class TestEntropyAnalyzer:
    """Tests for EntropyAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    @pytest.fixture
    def pafish_exe(self):
        """Path to pafish.exe PE binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "pafish.exe"

    def test_analyze_file_elf(self, ls_elf):
        """Test entropy analysis on ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        assert isinstance(result, EntropyResult)
        assert 0 <= result.overall_entropy <= 8.0
        assert isinstance(result.section_entropies, dict)
        assert isinstance(result.suspicious_sections, list)
        assert isinstance(result.is_packed, bool)
        assert isinstance(result.analysis, str)

    def test_analyze_file_pe(self, pafish_exe):
        """Test entropy analysis on PE binary."""
        if not pafish_exe.exists():
            pytest.skip("PE binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(pafish_exe)

        assert isinstance(result, EntropyResult)
        assert 0 <= result.overall_entropy <= 8.0
        assert isinstance(result.is_packed, bool)

    def test_entropy_result_str(self, ls_elf):
        """Test EntropyResult string representation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        result_str = str(result)
        assert "Entropy Analysis" in result_str
        assert "Overall:" in result_str

    def test_entropy_thresholds(self, ls_elf):
        """Test entropy threshold detection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        assert analyzer.HIGH_ENTROPY_THRESHOLD == 7.0
        assert analyzer.SUSPICIOUS_ENTROPY_THRESHOLD == 6.5

    def test_suspicious_sections(self, pafish_exe):
        """Test detection of suspicious high-entropy sections."""
        if not pafish_exe.exists():
            pytest.skip("PE binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(pafish_exe)

        assert isinstance(result.suspicious_sections, list)
        for section in result.suspicious_sections:
            assert isinstance(section, str)


class TestEvasionScorer:
    """Tests for EvasionScorer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

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

        assert isinstance(result, EvasionScore)
        assert 0 <= result.overall_score <= 100
        assert 0 <= result.hash_change_score <= 100
        assert 0 <= result.entropy_score <= 100
        assert 0 <= result.structure_score <= 100
        assert 0 <= result.signature_score <= 100
        assert isinstance(result.details, dict)

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
        assert "Evasion Score:" in result_str
        assert "Hash Change:" in result_str
        assert "Entropy:" in result_str

    def test_scorer_weights(self):
        """Test evasion scorer weights."""
        scorer = EvasionScorer()

        assert "hash_change" in scorer.weights
        assert "entropy" in scorer.weights
        assert "structure" in scorer.weights
        assert "signature" in scorer.weights

        total_weight = sum(scorer.weights.values())
        assert abs(total_weight - 1.0) < 0.01

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

        assert result.details.get("hash_changed") is not None


class TestSimilarityHasher:
    """Tests for SimilarityHasher."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_hasher_initialization(self):
        """Test SimilarityHasher initialization."""
        hasher = SimilarityHasher()

        assert isinstance(hasher.has_ssdeep, bool)
        assert isinstance(hasher.has_tlsh, bool)

    def test_hash_file(self, ls_elf):
        """Test file hashing."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        result = hasher.hash_file(ls_elf)

        assert isinstance(result, dict)
        assert "ssdeep" in result
        assert "tlsh" in result

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

        assert isinstance(original_hashes, dict)
        assert isinstance(morphed_hashes, dict)

    def test_tool_check(self):
        """Test tool availability check."""
        hasher = SimilarityHasher()

        result = hasher._check_tool("ls")
        assert isinstance(result, bool)
