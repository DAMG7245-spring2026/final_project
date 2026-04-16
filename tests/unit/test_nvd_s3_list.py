"""S3 list_objects helper for NVD staging."""

from unittest.mock import MagicMock, patch

from ingestion.nvd.s3_io import list_s3_keys


@patch("ingestion.nvd.s3_io.get_s3_client")
def test_list_s3_keys_paginates_and_sorts(mock_get_client):
    cli = MagicMock()
    mock_get_client.return_value = cli
    cli.list_objects_v2.side_effect = [
        {
            "Contents": [
                {"Key": "nvd/raw/2024-02.jsonl"},
                {"Key": "nvd/raw/2024-01.jsonl"},
            ],
            "IsTruncated": True,
            "NextContinuationToken": "tok1",
        },
        {
            "Contents": [{"Key": "nvd/raw/2024-03.jsonl"}],
            "IsTruncated": False,
        },
    ]
    keys = list_s3_keys("my-bucket", "nvd")
    assert keys == [
        "nvd/raw/2024-01.jsonl",
        "nvd/raw/2024-02.jsonl",
        "nvd/raw/2024-03.jsonl",
    ]
    assert cli.list_objects_v2.call_count == 2
    first_kw = cli.list_objects_v2.call_args_list[0][1]
    assert first_kw["Bucket"] == "my-bucket"
    assert first_kw["Prefix"] == "nvd/"


@patch("ingestion.nvd.s3_io.get_s3_client")
def test_list_s3_keys_empty(mock_get_client):
    mock_get_client.return_value.list_objects_v2.return_value = {}
    assert list_s3_keys("b", "prefix") == []
