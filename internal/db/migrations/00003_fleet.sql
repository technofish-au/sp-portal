-- Fleet: registered on-prem appliances (instances), their periodic reports
-- and the daily telemetry rollups.
--
-- +goose Up
CREATE TABLE instances (
    id                CHAR(36)     NOT NULL,
    org_id            CHAR(36)     NOT NULL,
    licence_id        CHAR(36)     DEFAULT NULL,
    name              VARCHAR(200) NOT NULL DEFAULT '',
    -- Stable appliance identity (e.g. machine-id hash); unique per org so
    -- re-registration of the same appliance updates rather than duplicates.
    fingerprint       VARCHAR(128) NOT NULL,
    appliance_version VARCHAR(64)  NOT NULL DEFAULT '',
    status            VARCHAR(16)  NOT NULL DEFAULT 'active',
    last_seen_at      DATETIME(6)  DEFAULT NULL,
    created_at        DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at        DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                   ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT instances_pkey PRIMARY KEY (id),
    CONSTRAINT instances_org_fingerprint_key UNIQUE (org_id, fingerprint),
    CONSTRAINT instances_status_check CHECK (status IN ('active', 'suspended', 'decommissioned')),
    CONSTRAINT instances_org_fkey FOREIGN KEY (org_id)
        REFERENCES organisations (id) ON DELETE CASCADE,
    CONSTRAINT instances_licence_fkey FOREIGN KEY (licence_id)
        REFERENCES licences (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX instances_org_idx ON instances (org_id, status);
CREATE INDEX instances_licence_idx ON instances (licence_id);

-- instance_reports is the append-only stream of appliance check-ins; the
-- JSON payload carries version/fleet counts whatever shape the appliance
-- reports.
CREATE TABLE instance_reports (
    id          CHAR(36)    NOT NULL,
    instance_id CHAR(36)    NOT NULL,
    reported_at DATETIME(6) NOT NULL,
    payload     JSON        NOT NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT instance_reports_pkey PRIMARY KEY (id),
    CONSTRAINT instance_reports_instance_fkey FOREIGN KEY (instance_id)
        REFERENCES instances (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX instance_reports_instance_idx ON instance_reports (instance_id, reported_at);

-- telemetry_daily is the per-instance, per-day rollup used for licence
-- compliance and usage reporting.
CREATE TABLE telemetry_daily (
    id             CHAR(36)     NOT NULL,
    org_id         CHAR(36)     NOT NULL,
    instance_id    CHAR(36)     NOT NULL,
    day            DATE         NOT NULL,
    machines_count INT          NOT NULL DEFAULT 0,
    metrics        JSON         NOT NULL,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT telemetry_daily_pkey PRIMARY KEY (id),
    CONSTRAINT telemetry_daily_instance_day_key UNIQUE (instance_id, day),
    CONSTRAINT telemetry_daily_org_fkey FOREIGN KEY (org_id)
        REFERENCES organisations (id) ON DELETE CASCADE,
    CONSTRAINT telemetry_daily_instance_fkey FOREIGN KEY (instance_id)
        REFERENCES instances (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX telemetry_daily_org_day_idx ON telemetry_daily (org_id, day);

