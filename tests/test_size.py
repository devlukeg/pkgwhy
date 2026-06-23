from pkgwhy.inspection.size import measure_distribution_size


def test_measure_distribution_size_handles_missing_distribution() -> None:
    size = measure_distribution_size(None)

    assert size.total_bytes == 0
    assert size.file_count == 0

