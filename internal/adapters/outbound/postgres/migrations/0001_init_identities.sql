-- +goose Up
-- IF NOT EXISTS: safe to run once against a database that already has
-- these tables from the old hand-applied schema.sql, so upgrading an
-- existing dev/staging deployment onto goose doesn't require a manual
-- reconciliation step.
CREATE TABLE IF NOT EXISTS identities (
    id               TEXT PRIMARY KEY,
    full_name        TEXT NOT NULL,
    email            TEXT NOT NULL UNIQUE,
    primary_provider TEXT NOT NULL,
    status           TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_providers (
    provider         TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    ecosystem_id     TEXT NOT NULL REFERENCES identities(id),
    PRIMARY KEY (provider, provider_user_id)
);

-- +goose Down
DROP TABLE IF EXISTS identity_providers;
DROP TABLE IF EXISTS identities;
