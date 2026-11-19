-- Schema gaps found by the R5-2/R5-3 waves: real columns replace the
-- audit_log workarounds those waves shipped with. audit_log rows keep
-- being written as the event record; these columns hold the state.
--
-- Deliberately NOT added: a sessions table. R5-3 sessions are stateless
-- HMAC cookies bound to a credential fingerprint — credential change or
-- disable kills them, which is the revocation guarantee we need. If a
-- "list/revoke sessions" feature ever lands, it gets its own migration.
--
-- +goose Up

-- Email-verified state on the account itself (was an audit-only fact).
ALTER TABLE users
    ADD COLUMN email_verified_at DATETIME(6) DEFAULT NULL AFTER totp_enabled;

-- Instance public key binding + clone flag (SP-Ed25519 auth, clone
-- detection) — the audit rows remain as history.
ALTER TABLE instances
    ADD COLUMN public_key          BINARY(32)  DEFAULT NULL AFTER fingerprint,
    ADD COLUMN suspected_clone_at  DATETIME(6) DEFAULT NULL AFTER last_seen_at;

-- Hash of the signed licence document issued for a licence.
ALTER TABLE licences
    ADD COLUMN doc_hash BINARY(32) DEFAULT NULL AFTER licence_key;
CREATE INDEX licences_doc_hash_idx ON licences (doc_hash);

-- Billing grace expiry lands on its own state instead of overloading
-- 'unpaid'.
ALTER TABLE subscriptions
    DROP CONSTRAINT subscriptions_status_check,
    ADD CONSTRAINT subscriptions_status_check CHECK (status IN
        ('trialing', 'active', 'past_due', 'suspended', 'unpaid',
         'cancelled', 'incomplete', 'incomplete_expired'));

-- Customer tax id (e.g. ABN) captured at the org level; Stripe-side tax
-- ids still mirror it.
ALTER TABLE organisations
    ADD COLUMN tax_id VARCHAR(32) NOT NULL DEFAULT '' AFTER billing_email;

-- R5-2/R5-3 look up audit rows by target (instance bindings, clone flags);
-- worth an index regardless of the new columns.
CREATE INDEX audit_log_target_idx ON audit_log (target_type, target_id, created_at);
