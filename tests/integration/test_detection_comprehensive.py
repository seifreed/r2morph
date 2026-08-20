"""
Comprehensive real tests for detection modules.
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
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from r2morph.mutations import NopInsertionPass

_EXPECTED_0_0_100_0 = 100.0
_EXPECTED_0_0_100_0_2 = 100.0
_EXPECTED_0_0_8_0 = 8.0
_EXPECTED_RESULT_BYTE_SIMILARITY_100_0 = 100.0


class TestSimilarityHasherComprehensive:
    """Comprehensive tests for SimilarityHasher."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_hasher_init(self):
        """Test SimilarityHasher initialization."""
        hasher = SimilarityHasher()

        expect(hasher is not None)
        expect(isinstance(hasher.has_ssdeep, bool))
        expect(isinstance(hasher.has_tlsh, bool))

    def test_hash_file(self, ls_elf):
        """Test hashing a file."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        result = hasher.hash_file(ls_elf)

        expect(isinstance(result, dict))
        expect(not ("ssdeep" not in result))
        expect(not ("tlsh" not in result))

    def test_compare_files_same(self, ls_elf):
        """Test comparing a file with itself."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        result = hasher.compare_files(ls_elf, ls_elf)

        expect(isinstance(result, dict))
        expect(not ("byte_similarity" not in result))
        expect(result["byte_similarity"] == _EXPECTED_RESULT_BYTE_SIMILARITY_100_0)

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

        expect(isinstance(result, dict))
        expect(not ("byte_similarity" not in result))
        # Mutated binary may be different or same depending on whether mutations were applied
        expect(isinstance(result["byte_similarity"], float))
        expect(0.0 <= result["byte_similarity"] <= _EXPECTED_0_0_100_0)


class TestEntropyAnalyzerComprehensive:
    """Comprehensive tests for EntropyAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_analyzer_init(self):
        """Test EntropyAnalyzer initialization."""
        analyzer = EntropyAnalyzer()

        expect(analyzer is not None)

    def test_analyze_file(self, ls_elf):
        """Test analyzing a file."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        expect(result is not None)
        expect(hasattr(result, "overall_entropy"))
        expect(isinstance(result.overall_entropy, float))
        expect(0.0 <= result.overall_entropy <= _EXPECTED_0_0_8_0)

    def test_is_packed(self, ls_elf):
        """Test checking if binary is packed."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        expect(isinstance(result.is_packed, bool))

    def test_suspicious_sections(self, ls_elf):
        """Test getting suspicious sections."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        expect(isinstance(result.suspicious_sections, list))


class TestEvasionScorerComprehensive:
    """Comprehensive tests for EvasionScorer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_scorer_init(self):
        """Test EvasionScorer initialization."""
        scorer = EvasionScorer()

        expect(scorer is not None)
        expect(hasattr(scorer, "weights"))

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

        expect(score is not None)
        expect(hasattr(score, "overall_score"))
        expect(isinstance(score.overall_score, float))
        expect(0.0 <= score.overall_score <= _EXPECTED_0_0_100_0_2)

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

        expect(hasattr(score, "hash_change_score"))
        expect(hasattr(score, "entropy_score"))
        expect(hasattr(score, "structure_score"))
        expect(hasattr(score, "signature_score"))
