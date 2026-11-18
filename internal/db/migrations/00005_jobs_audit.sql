-- Queue and audit: the jobs table backs the worker pool (claimed with
-- SELECT ... FOR UPDATE SKIP LOCKED, see internal/jobs); audit_log is the
-- append-only record of actor actions.
--
-- +goose Up
CREATE TABLE jobs (
    id           CHAR(36)      NOT NULL,
    -- Job type; a worker must have a Handler registered for it.
    kind         VARCHAR(64)   NOT NULL,
    payload      JSON          NOT NULL,
    -- Optional idempotency key: re-enqueueing the same key is a no-op.
    dedupe_key   VARCHAR(255)  DEFAULT NULL,
    status       VARCHAR(16)   NOT NULL DEFAULT 'pending',
    attempts     INT           NOT NULL DEFAULT 0,
    max_attempts INT           NOT NULL DEFAULT 8,
    -- Earliest time the job may be claimed; retries reschedule it with
    -- exponential backoff.
    run_at       DATETIME(6)   NOT NULL,
    claimed_by   VARCHAR(64)   DEFAULT NULL,
    claimed_at   DATETIME(6)   DEFAULT NULL,
    last_error   TEXT          DEFAULT NULL,
    created_at   DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at   DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                               ON UPDATE CURRENT_TIMESTAMP(6),
    finished_at  DATETIME(6)   DEFAULT NULL,
    CONSTRAINT jobs_pkey PRIMARY KEY (id),
    CONSTRAINT jobs_dedupe_key UNIQUE (dedupe_key),
    CONSTRAINT jobs_status_check CHECK (status IN ('pending', 'running', 'done', 'dead')),
    CONSTRAINT jobs_attempts_check CHECK (attempts >= 0 AND max_attempts >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- Claim scan: due pending jobs in run_at order.
CREATE INDEX jobs_claim_idx ON jobs (status, run_at, id);
-- Stale-claim reaper.
CREATE INDEX jobs_running_idx ON jobs (status, claimed_at);

-- audit_log is append-only; org_id/actor_user_id are deliberately not
-- foreign keys so deleting an org or user keeps the trail.
CREATE TABLE audit_log (
    id            CHAR(36)     NOT NULL,
    org_id        CHAR(36)     DEFAULT NULL,
    actor_user_id CHAR(36)     DEFAULT NULL,
    actor_email   VARCHAR(320) NOT NULL DEFAULT '',
    action        VARCHAR(128) NOT NULL,
    target_type   VARCHAR(64)  NOT NULL DEFAULT '',
    target_id     VARCHAR(64)  NOT NULL DEFAULT '',
    detail        JSON         DEFAULT NULL,
    ip            VARCHAR(45)  NOT NULL DEFAULT '',
    created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT audit_log_pkey PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX audit_log_org_idx ON audit_log (org_id, created_at);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_user_id, created_at);
CREATE INDEX audit_log_action_idx ON audit_log (action, created_at);

