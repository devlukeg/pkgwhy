from pkgwhy.inspection.size import NATIVE_SUFFIXES, measure_distribution_size


def test_measure_distribution_size_handles_missing_distribution() -> None:
    size = measure_distribution_size(None)

    assert size.total_bytes == 0
    assert size.file_count == 0


def test_native_suffixes_include_wasm_and_executables() -> None:
    assert ".wasm" in NATIVE_SUFFIXES
    assert ".exe" in NATIVE_SUFFIXES
