"""S3 URI helpers for slice-based NVD layout."""

from datetime import date

from ingestion.nvd.s3_slice_paths import slice_curated_s3_uri, slice_raw_s3_uri


def test_slice_raw_s3_uri():
    u = slice_raw_s3_uri("my-bucket", "nvd", date(2024, 1, 1), date(2024, 1, 7))
    assert u == "s3://my-bucket/nvd/raw/slices/2024-01-01_2024-01-07.jsonl"


def test_slice_curated_s3_uri():
    u = slice_curated_s3_uri("b", "prefix", date(2023, 12, 25), date(2023, 12, 31))
    assert u == "s3://b/prefix/curated/slices/2023-12-25_2023-12-31.ndjson"


def test_slice_uris_strip_slashes_in_prefix():
    r = slice_raw_s3_uri("x", "/p//", date(2024, 6, 1), date(2024, 6, 1))
    c = slice_curated_s3_uri("x", "  p2/  ", date(2024, 6, 1), date(2024, 6, 2))
    assert "/p/raw/slices/" in r
    assert "/p2/curated/slices/" in c
