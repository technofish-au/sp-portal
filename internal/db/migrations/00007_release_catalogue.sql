-- R5-4 release catalogue: the columns the catalogue admin API needs on
-- releases. min_upgrade_from floors the appliance version that may apply
-- the release (empty = no floor), security marks the release as a
-- security fix (surfaced to appliances at check-in), withdrawn_at marks
-- a published release pulled from distribution (published_at keeps the
-- history; "published" means published_at IS NOT NULL AND withdrawn_at
-- IS NULL).
--
-- +goose Up
ALTER TABLE releases
    ADD COLUMN min_upgrade_from VARCHAR(64) NOT NULL DEFAULT '' AFTER notes,
    ADD COLUMN security         TINYINT(1)  NOT NULL DEFAULT 0 AFTER min_upgrade_from,
    ADD COLUMN withdrawn_at     DATETIME(6) DEFAULT NULL AFTER published_at;
