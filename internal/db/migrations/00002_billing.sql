-- Billing: Stripe subscriptions, issued licence keys and the stripe_events
-- inbox whose unique event_id makes webhook processing idempotent.
--
-- +goose Up
CREATE TABLE subscriptions (
    id                     CHAR(36)     NOT NULL,
    org_id                 CHAR(36)     NOT NULL,
    stripe_subscription_id VARCHAR(64)  DEFAULT NULL,
    stripe_price_id        VARCHAR(64)  NOT NULL DEFAULT '',
    plan                   VARCHAR(16)  NOT NULL DEFAULT 'trial',
    status                 VARCHAR(24)  NOT NULL DEFAULT 'trialing',
    seats                  INT          NOT NULL DEFAULT 1,
    current_period_start   DATETIME(6)  DEFAULT NULL,
    current_period_end     DATETIME(6)  DEFAULT NULL,
    cancel_at              DATETIME(6)  DEFAULT NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                       ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT subscriptions_pkey PRIMARY KEY (id),
    CONSTRAINT subscriptions_stripe_key UNIQUE (stripe_subscription_id),
    CONSTRAINT subscriptions_plan_check CHECK (plan IN ('trial', 'starter', 'pro', 'enterprise')),
    CONSTRAINT subscriptions_status_check CHECK (status IN
        ('trialing', 'active', 'past_due', 'unpaid', 'cancelled',
         'incomplete', 'incomplete_expired')),
    CONSTRAINT subscriptions_seats_check CHECK (seats >= 1),
    CONSTRAINT subscriptions_org_fkey FOREIGN KEY (org_id)
        REFERENCES organisations (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX subscriptions_org_idx ON subscriptions (org_id, status);

-- licences are the signed licence documents appliances activate against.
-- licence_key is the unique public identifier embedded in the signed token.
CREATE TABLE licences (
    id              CHAR(36)     NOT NULL,
    org_id          CHAR(36)     NOT NULL,
    subscription_id CHAR(36)     DEFAULT NULL,
    licence_key     VARCHAR(128) NOT NULL,
    kind            VARCHAR(16)  NOT NULL DEFAULT 'subscription',
    plan            VARCHAR(16)  NOT NULL DEFAULT 'trial',
    max_instances   INT          NOT NULL DEFAULT 1,
    issued_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at      DATETIME(6)  DEFAULT NULL,
    revoked_at      DATETIME(6)  DEFAULT NULL,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                 ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT licences_pkey PRIMARY KEY (id),
    CONSTRAINT licences_key_key UNIQUE (licence_key),
    CONSTRAINT licences_kind_check CHECK (kind IN ('trial', 'subscription', 'perpetual')),
    CONSTRAINT licences_plan_check CHECK (plan IN ('trial', 'starter', 'pro', 'enterprise')),
    CONSTRAINT licences_max_instances_check CHECK (max_instances >= 1),
    CONSTRAINT licences_org_fkey FOREIGN KEY (org_id)
        REFERENCES organisations (id) ON DELETE CASCADE,
    CONSTRAINT licences_subscription_fkey FOREIGN KEY (subscription_id)
        REFERENCES subscriptions (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX licences_org_idx ON licences (org_id, revoked_at);

-- stripe_events is the webhook inbox: one row per received Stripe event,
-- claimed by event_id so redeliveries are no-ops (idempotent processing).
CREATE TABLE stripe_events (
    id            CHAR(36)     NOT NULL,
    event_id      VARCHAR(128) NOT NULL,
    type          VARCHAR(128) NOT NULL,
    livemode      TINYINT(1)   NOT NULL DEFAULT 0,
    payload       JSON         NOT NULL,
    processed_at  DATETIME(6)  DEFAULT NULL,
    process_error TEXT         DEFAULT NULL,
    created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT stripe_events_pkey PRIMARY KEY (id),
    CONSTRAINT stripe_events_event_id_key UNIQUE (event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX stripe_events_type_idx ON stripe_events (type, created_at);
CREATE INDEX stripe_events_unprocessed_idx ON stripe_events (processed_at);

