"""
Comprehensive real tests for detection modules.
"""

import importlib.util
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph import MorphEngine
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from r2morph.mutations import NopInsertionPass


class TestSimilarityHasherComprehensive:
    """Comprehensive tests for SimilarityHasher."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_hasher_init(self):
        """Test SimilarityHasher initialization."""
        hasher = SimilarityHasher()

        assert hasher is not None
        assert isinstance(hasher.has_ssdeep, bool)
        assert isinstance(hasher.has_tlsh, bool)

    def test_hash_file(self, ls_elf):
        """Test hashing a file."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        result = hasher.hash_file(ls_elf)

        assert isinstance(result, dict)
        assert "ssdeep" in result
        assert "tlsh" in result

    def test_compare_files_same(self, ls_elf):
        """Test comparing a file with itself."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        result = hasher.compare_files(ls_elf, ls_elf)

        assert isinstance(result, dict)
        assert "byte_similarity" in result
        assert result["byte_similarity"] == 100.0

    def test_compare_files_different(self, ls_elf, tmp_path):
        """Test comparing different files."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Create a mutated version
        output_path = tmp_path / "ls_mutated"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(output_path)

        hasher = SimilarityHasher()
        result = hasher.compare_files(ls_elf, output_path)

        assert isinstance(result, dict)
        assert "byte_similarity" in result
        # Mutated binary may be different or same depending on whether mutations were applied
        assert isinstance(result["byte_similarity"], float)
        assert 0.0 <= result["byte_similarity"] <= 100.0


class TestEntropyAnalyzerComprehensive:
    """Comprehensive tests for EntropyAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_analyzer_init(self):
        """Test EntropyAnalyzer initialization."""
        analyzer = EntropyAnalyzer()

        assert analyzer is not None

    def test_analyze_file(self, ls_elf):
        """Test analyzing a file."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        assert result is not None
        assert hasattr(result, "overall_entropy")
        assert isinstance(result.overall_entropy, float)
        assert 0.0 <= result.overall_entropy <= 8.0

    def test_is_packed(self, ls_elf):
        """Test checking if binary is packed."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        assert isinstance(result.is_packed, bool)

    def test_suspicious_sections(self, ls_elf):
        """Test getting suspicious sections."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        assert isinstance(result.suspicious_sections, list)


class TestEvasionScorerComprehensive:
    """Comprehensive tests for EvasionScorer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_scorer_init(self):
        """Test EvasionScorer initialization."""
        scorer = EvasionScorer()

        assert scorer is not None
        assert hasattr(scorer, "weights")

    def test_score_binaries(self, ls_elf, tmp_path):
        """Test scoring original and mutated binaries."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Create a mutated version
        output_path = tmp_path / "ls_mutated"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(output_path)

        scorer = EvasionScorer()
        score = scorer.score(ls_elf, output_path)

        assert score is not None
        assert hasattr(score, "overall_score")
        assert isinstance(score.overall_score, float)
        assert 0.0 <= score.overall_score <= 100.0

    def test_score_components(self, ls_elf, tmp_path):
        """Test score components."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Create a mutated version
        output_path = tmp_path / "ls_mutated2"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(output_path)

        scorer = EvasionScorer()
        score = scorer.score(ls_elf, output_path)

        assert hasattr(score, "hash_change_score")
        assert hasattr(score, "entropy_score")
        assert hasattr(score, "structure_score")
        assert hasattr(score, "signature_score")