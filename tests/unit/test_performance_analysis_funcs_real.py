from r2morph.performance import create_detection_analysis_func, create_devirtualization_analysis_func


def test_detection_analysis_func_runs_on_dataset():
    analyze = create_detection_analysis_func()
    result = analyze("dataset/elf_x86_64")
    assert isinstance(result, dict)
    assert "analysis_type" not in result
    assert "confidence_score" in result or "error" in result


def test_devirtualization_analysis_func_runs_on_dataset():
    analyze = create_devirtualization_analysis_func()
    result = analyze("dataset/elf_x86_64")
    assert isinstance(result, dict)
    assert "functions_analyzed" in result or "error" in result
