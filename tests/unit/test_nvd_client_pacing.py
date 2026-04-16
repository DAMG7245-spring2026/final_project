"""NVD client request pacing (no HTTP)."""

from unittest.mock import MagicMock, patch

import pytest

from ingestion.nvd.client import (
    PACE_NO_API_KEY_SEC,
    PACE_WITH_API_KEY_SEC,
    resolve_nvd_request_interval,
)


@pytest.fixture
def mock_get_settings():
    with patch("app.config.get_settings") as m:
        s = MagicMock()
        s.nvd_min_request_interval_sec = None
        m.return_value = s
        yield m


def test_resolve_no_api_key_uses_six_second_default(mock_get_settings):
    assert resolve_nvd_request_interval(None) == PACE_NO_API_KEY_SEC


def test_resolve_with_api_key_uses_faster_default(mock_get_settings):
    assert resolve_nvd_request_interval("secret") == PACE_WITH_API_KEY_SEC


def test_resolve_settings_override_wins_over_key_defaults(mock_get_settings):
    mock_get_settings.return_value.nvd_min_request_interval_sec = 2.5
    assert resolve_nvd_request_interval(None) == 2.5
    assert resolve_nvd_request_interval("key") == 2.5


def test_explicit_override_wins_over_everything(mock_get_settings):
    mock_get_settings.return_value.nvd_min_request_interval_sec = 2.5
    assert resolve_nvd_request_interval("key", explicit_override=1.25) == 1.25
