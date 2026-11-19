-- R5-5 portal UI: per-user, per-org notification preferences. The
-- portal emails customers when an instance falls behind, when a security
-- release applies and when a licence nears expiry; each is opt-out per
-- user per org. Billing-failure mail is never opt-out — the
-- notify_billing column exists so the shape is explicit, and the API
-- forces it back on at write time.
--
-- +goose Up
CREATE TABLE notification_prefs (
    org_id                  CHAR(36)    NOT NULL,
    user_id                 CHAR(36)    NOT NULL,
    notify_version_behind   TINYINT(1)  NOT NULL DEFAULT 1,
    notify_security_release TINYINT(1)  NOT NULL DEFAULT 1,
    notify_licence_expiry   TINYINT(1)  NOT NULL DEFAULT 1,
    notify_billing          TINYINT(1)  NOT NULL DEFAULT 1,
    created_at              DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at              DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                        ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT notification_prefs_pkey PRIMARY KEY (org_id, user_id),
    CONSTRAINT notification_prefs_org_fkey FOREIGN KEY (org_id)
        REFERENCES organisations (id) ON DELETE CASCADE,
    CONSTRAINT notification_prefs_user_fkey FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
