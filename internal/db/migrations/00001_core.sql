-- Core identity model: organisations (customers), portal users and the
-- memberships joining them. Primary keys are UUID text (CHAR(36)) —
-- generated application-side (uuid v7) so ids stay consistent across the
-- schema. All timestamps are UTC (UTC_TIMESTAMP defaults are set
-- application-side for inserts; created_at/updated_at default to now).
--
-- +goose Up
CREATE TABLE organisations (
    id                 CHAR(36)     NOT NULL,
    name               VARCHAR(200) NOT NULL,
    slug               VARCHAR(80)  NOT NULL,
    billing_email      VARCHAR(320) NOT NULL DEFAULT '',
    -- Stripe customer id (cus_...); NULL until the org is linked.
    stripe_customer_id VARCHAR(64)  DEFAULT NULL,
    created_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                    ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT organisations_pkey PRIMARY KEY (id),
    CONSTRAINT organisations_slug_key UNIQUE (slug),
    CONSTRAINT organisations_stripe_customer_key UNIQUE (stripe_customer_id),
    CONSTRAINT organisations_slug_check CHECK (slug <> '')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE users (
    id                 CHAR(36)     NOT NULL,
    -- Stored normalised (lower-case); utf8mb4_unicode_ci is
    -- case-insensitive so the unique key enforces it either way.
    email              VARCHAR(320) NOT NULL,
    display_name       VARCHAR(200) NOT NULL DEFAULT '',
    -- Argon2id PHC string; empty for invite-only/disabled-password users.
    password_hash      VARCHAR(255) NOT NULL DEFAULT '',
    -- Portal operators (technofish staff) vs customer accounts.
    is_platform_admin  TINYINT(1)   NOT NULL DEFAULT 0,
    -- TOTP shared secret, sealed at rest (envelope encryption).
    totp_secret_enc    BLOB         DEFAULT NULL,
    totp_enabled       TINYINT(1)   NOT NULL DEFAULT 0,
    disabled_at        DATETIME(6)  DEFAULT NULL,
    created_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                    ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_email_key UNIQUE (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE memberships (
    id         CHAR(36)    NOT NULL,
    org_id     CHAR(36)    NOT NULL,
    user_id    CHAR(36)    NOT NULL,
    role       VARCHAR(16) NOT NULL DEFAULT 'member',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT memberships_pkey PRIMARY KEY (id),
    CONSTRAINT memberships_org_user_key UNIQUE (org_id, user_id),
    CONSTRAINT memberships_role_check CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    CONSTRAINT memberships_org_fkey FOREIGN KEY (org_id)
        REFERENCES organisations (id) ON DELETE CASCADE,
    CONSTRAINT memberships_user_fkey FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX memberships_user_idx ON memberships (user_id, org_id);

