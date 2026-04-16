"""S3 URI parsing for NVD staging."""

import pytest

from ingestion.nvd.s3_io import is_s3_uri, parse_s3_uri


def test_parse_s3_uri_ok():
    assert parse_s3_uri("s3://my-bucket/nvd/raw/2024-01.jsonl") == (
        "my-bucket",
        "nvd/raw/2024-01.jsonl",
    )


def test_parse_s3_uri_key_with_slashes():
    b, k = parse_s3_uri("s3://b/prefix/more/key.ndjson")
    assert b == "b"
    assert k == "prefix/more/key.ndjson"


@pytest.mark.parametrize(
    "bad",
    [
        "http://bucket/key",
        "s3://bucket",
        "s3://bucket/",
        "s3://",
        "bucket/key",
    ],
)
def test_parse_s3_uri_invalid(bad: str):
    with pytest.raises(ValueError):
        parse_s3_uri(bad)


def test_is_s3_uri():
    assert is_s3_uri("s3://a/b")
    assert not is_s3_uri("data/nvd/raw/x.jsonl")
