CREATE TABLE IF NOT EXISTS llm_token_log (
    log_id            VARCHAR(36)   NOT NULL DEFAULT UUID_STRING(),
    called_at         TIMESTAMP_TZ  NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    pipeline_stage    VARCHAR(64)   NOT NULL,
    model             VARCHAR(64)   NOT NULL,
    request_id        VARCHAR(32),
    prompt_tokens     INTEGER       NOT NULL,
    completion_tokens INTEGER       NOT NULL,
    total_tokens      INTEGER       NOT NULL,
    advisory_id       VARCHAR(64),
    PRIMARY KEY (log_id)
);
