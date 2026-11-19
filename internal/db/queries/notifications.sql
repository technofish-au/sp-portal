-- Per-user, per-org notification preferences (R5-5, migration 00008).
-- A missing row means "all defaults on"; the read side substitutes them.

-- name: GetNotificationPrefs :one
SELECT org_id, user_id, notify_version_behind, notify_security_release,
       notify_licence_expiry, notify_billing, created_at, updated_at
  FROM notification_prefs WHERE org_id = ? AND user_id = ?;

-- name: UpsertNotificationPrefs :exec
INSERT INTO notification_prefs (org_id, user_id, notify_version_behind,
                                notify_security_release, notify_licence_expiry,
                                notify_billing)
VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    notify_version_behind = VALUES(notify_version_behind),
    notify_security_release = VALUES(notify_security_release),
    notify_licence_expiry = VALUES(notify_licence_expiry),
    notify_billing = VALUES(notify_billing);
