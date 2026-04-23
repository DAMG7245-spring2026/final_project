CREATE OR REPLACE VIEW llm_cost_breakdown AS
SELECT
    pipeline_stage,
    COUNT(*)                                              AS call_count,
    SUM(prompt_tokens)                                    AS total_prompt_tokens,
    SUM(completion_tokens)                                AS total_completion_tokens,
    SUM(total_tokens)                                     AS total_tokens,
    MIN(called_at)                                        AS first_call,
    MAX(called_at)                                        AS last_call
FROM llm_token_log
GROUP BY pipeline_stage
ORDER BY total_tokens DESC;
