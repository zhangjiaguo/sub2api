-- 打票（OpenAI Codex turn-state 采集）相关表。
-- 机制：用短探测请求（"Reply with OK."）经动态代理出口打 /backend-api/codex/responses，
-- 从响应头 x-codex-turn-state 采集票据；有效票据 = 封装合法且长度/块数符合期望
-- （实测 gpt-6-astra 为 780 字符 / 33 块）。

-- 当前票据：每账号一行，保留最新一张（含采集时的出口 IP，便于观测动态出口落点）。
CREATE TABLE IF NOT EXISTS openai_codex_tickets (
    account_id      BIGINT PRIMARY KEY,
    value           TEXT NOT NULL,
    state_length    INT NOT NULL,
    blocks          INT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    exit_ip         TEXT,
    exit_colo       TEXT,
    fingerprint     TEXT NOT NULL DEFAULT '',
    model           TEXT NOT NULL DEFAULT '',
    plan_type       TEXT NOT NULL DEFAULT '',
    used_percent    TEXT NOT NULL DEFAULT '',
    http_status     INT NOT NULL DEFAULT 0,
    duration_ms     INT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 打票日志：成功率 / 有效率统计与排障依据。
CREATE TABLE IF NOT EXISTS openai_codex_ticket_grab_logs (
    id              BIGSERIAL PRIMARY KEY,
    account_id      BIGINT NOT NULL,
    result          VARCHAR(40) NOT NULL,
    http_status     INT NOT NULL DEFAULT 0,
    state_length    INT NOT NULL DEFAULT 0,
    blocks          INT NOT NULL DEFAULT 0,
    exit_ip         TEXT,
    exit_colo       TEXT,
    detail          TEXT,
    duration_ms     INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ticket_grab_logs_account_created ON openai_codex_ticket_grab_logs(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ticket_grab_logs_created ON openai_codex_ticket_grab_logs(created_at DESC);
