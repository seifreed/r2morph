import platform
import shutil
from pathlib import Path

from r2morph.validation.validator import BinaryValidator
from tests.utils.assertions import expect
from tests.utils.platform_binaries import ensure_exists, get_platform_binary

_EXPECTED_RESULT_SIMILARITY_SCORE_100_0 = 100.0
_EXPECTED_RESULT_SIMILARITY_SCORE_100_0_2 = 100.0
_VALIDATION_TIMEOUT_SECONDS = 60


def test_validator_round_trip_same_binary(tmp_path):
    src = get_platform_binary("generic")
    if not ensure_exists(src):
        raise RuntimeError("No platform binary available for validator test")
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    shutil.copy2(src, original)
    shutil.copy2(src, mutated)

    validator = BinaryValidator(timeout=_VALIDATION_TIMEOUT_SECONDS)
    validator.add_test_case(description="default run")
    result = validator.validate(original, mutated)
    expect(not (result.passed is not True))
    expect(result.similarity_score == _EXPECTED_RESULT_SIMILARITY_SCORE_100_0)


def test_validator_timeout_path(tmp_path):
    if platform.system() == "Windows":
        return
    sleep_bin = Path("/bin/sleep")
    if not sleep_bin.exists():
        raise RuntimeError("sleep binary not available")
    original = tmp_path / "sleep_original"
    mutated = tmp_path / "sleep_mutated"
    shutil.copyfile(sleep_bin, original)
    shutil.copyfile(sleep_bin, mutated)
    original.chmod(0o755)
    mutated.chmod(0o755)

    validator = BinaryValidator(timeout=1)
    validator.add_test_case(args=["2"], description="timeout test")
    result = validator.validate(original, mutated)
    expect(not (result.passed is not True))
    expect(result.similarity_score == _EXPECTED_RESULT_SIMILARITY_SCORE_100_0_2)
