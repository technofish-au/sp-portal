-- Distribution: released artifacts, uploaded support bundles and the
-- signed download tokens that gate both.
--
-- +goose Up
CREATE TABLE releases (
    id            CHAR(36)     NOT NULL,
    version       VARCHAR(64)  NOT NULL,
    component     VARCHAR(16)  NOT NULL DEFAULT 'platform',
    channel       VARCHAR(16)  NOT NULL DEFAULT 'stable',
    notes         TEXT         NOT NULL,
    -- Path of the artifact relative to storage_dir/releases/.
    artifact_path VARCHAR(500) NOT NULL DEFAULT '',
    sha256        CHAR(64)     NOT NULL DEFAULT '',
    size_bytes    BIGINT       NOT NULL DEFAULT 0,
    published_at  DATETIME(6)  DEFAULT NULL,
    created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                               ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT releases_pkey PRIMARY KEY (id),
    CONSTRAINT releases_component_version_key UNIQUE (component, version),
    CONSTRAINT releases_component_check CHECK (component IN ('platform', 'client', 'docs')),
    CONSTRAINT releases_channel_check CHECK (channel IN ('stable', 'beta', 'rc')),
    CONSTRAINT releases_size_check CHECK (size_bytes >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX releases_channel_idx ON releases (channel, published_at);

-- support_bundles are diagnostic archives uploaded by appliances or
-- customers; files live under storage_dir/support-bundles/<org>/<id>.
CREATE TABLE support_bundles (
    id          CHAR(36)     NOT NULL,
    org_id      CHAR(36)     NOT NULL,
    instance_id CHAR(36)     DEFAULT NULL,
    -- Path relative to storage_dir/support-bundles/.
    path        VARCHAR(500) NOT NULL DEFAULT '',
    size_bytes  BIGINT       NOT NULL DEFAULT 0,
    uploaded_by CHAR(36)     DEFAULT NULL,
    uploaded_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at  DATETIME(6)  DEFAULT NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT support_bundles_pkey PRIMARY KEY (id),
    CONSTRAINT support_bundles_size_check CHECK (size_bytes >= 0),
    CONSTRAINT support_bundles_org_fkey FOREIGN KEY (org_id)
        REFERENCES organisations (id) ON DELETE CASCADE,
    CONSTRAINT support_bundles_instance_fkey FOREIGN KEY (instance_id)
        REFERENCES instances (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX support_bundles_org_idx ON support_bundles (org_id, uploaded_at);
CREATE INDEX support_bundles_expiry_idx ON support_bundles (expires_at);

-- download_tokens gate artifact downloads (release binaries, offline
-- bundles, support bundles, apt repo access). Only the SHA-256 of the
-- bearer token is stored.
CREATE TABLE download_tokens (
    id         CHAR(36)     NOT NULL,
    token_hash CHAR(64)     NOT NULL,
    org_id     CHAR(36)     DEFAULT NULL,
    kind       VARCHAR(16)  NOT NULL,
    -- storage_dir-relative path the token authorises, or a release id.
    path       VARCHAR(500) NOT NULL DEFAULT '',
    release_id CHAR(36)     DEFAULT NULL,
    expires_at DATETIME(6)  NOT NULL,
    used_at    DATETIME(6)  DEFAULT NULL,
    created_by CHAR(36)     DEFAULT NULL,
    created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT download_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT download_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT download_tokens_kind_check CHECK (kind IN
        ('release', 'offline_bundle', 'support_bundle', 'apt')),
    CONSTRAINT download_tokens_org_fkey FOREIGN KEY (org_id)
        REFERENCES organisations (id) ON DELETE CASCADE,
    CONSTRAINT download_tokens_release_fkey FOREIGN KEY (release_id)
        REFERENCES releases (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX download_tokens_expiry_idx ON download_tokens (expires_at);
CREATE INDEX download_tokens_org_idx ON download_tokens (org_id);

