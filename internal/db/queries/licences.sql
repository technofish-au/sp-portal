-- name: CreateLicence :exec
INSERT INTO licences (id, org_id, subscription_id, licence_key, kind, plan,
                      max_instances, issued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
