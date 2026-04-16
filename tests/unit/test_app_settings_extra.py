"""Settings tolerates Docker/Airflow-only env vars in the same .env file."""

from app.config import Settings


def test_settings_ignores_unknown_env_keys(monkeypatch):
    monkeypatch.setenv("AIRFLOW_FERNET_KEY", "not-a-model-field")
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "testacct")
    s = Settings()
    assert s.snowflake_account == "testacct"
