import shutil
from pathlib import Path

from r2morph.validation.validator import BinaryValidator


def test_validator_round_trip_same_binary(tmp_path):
    src = Path("dataset/macho_arm64")
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    shutil.copy2(src, original)
    shutil.copy2(src, mutated)

    validator = BinaryValidator(timeout=5)
    validator.add_test_case(description="default run")
    result = validator.validate(original, mutated)
    assert result.passed is True
    assert result.similarity_score == 100.0


def test_validator_timeout_path(tmp_path):
    sleep_bin = Path("/bin/sleep")
    original = tmp_path / "sleep_original"
    mutated = tmp_path / "sleep_mutated"
    shutil.copyfile(sleep_bin, original)
    shutil.copyfile(sleep_bin, mutated)
    original.chmod(0o755)
    mutated.chmod(0o755)

    validator = BinaryValidator(timeout=1)
    validator.add_test_case(args=["2"], description="timeout test")
    result = validator.validate(original, mutated)
    assert result.passed is True
    assert result.similarity_score == 100.0
