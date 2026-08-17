-- Schema for the postgres IdentityRepository adapter (architecture plan §13).
-- Apply manually against DATABASE_URL before running the server.

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
