# IAM Microservice

## What this is

A standalone Identity & Access Management microservice for a multi-application
ecosystem. It centralizes SSO login (via Supabase Auth/GoTrue) behind a stable
internal interface, so applications trust only IAM-issued JWTs and never see
Supabase directly. Full design rationale lives in `IAM-Architecture-Plan.md`
(read this first for anything non-trivial) and the original requirements in
`IAM global 1-08-26.md`.

Module: `github.com/company/iam` (Go). Code lives under `iam/`.

## Architecture

Hexagonal (ports & adapters), strict dependency rule:

- `domain` — zero internal imports, stdlib only (`identity`, `provider`).
- `application` — depends only on `domain` + `ports`. Use cases live in
  `application/auth`, `application/ports/outbound` (interfaces the use
  cases require: `AuthProviderPort`, `IdentityRepository`, `TokenSigner`).
- `adapters` — implements ports. Inbound: `adapters/inbound/httpapi`
  (router, handlers, PKCE/state stores, middleware). Outbound:
  `adapters/outbound/supabase` (the *only* package allowed to know
  Supabase's wire format), `adapters/outbound/jwtsign` (Ed25519 JWT
  signer + JWKS), `adapters/outbound/memoryrepo` (dev-only in-memory
  identity store — not durable, not multi-replica safe).
- `cmd/server` — the only package allowed to import concrete adapters;
  wires everything from `internal/config` and starts the HTTP server.
- `cmd/genkey` — dev helper, generates an Ed25519 keypair for
  `JWT_PRIVATE_KEY`.

Key invariant: **IAM never forwards a Supabase-issued token to an
application.** `supabase.Adapter.ExchangeCode` returns a normalized
`ExternalIdentity`; the `auth.Service` use case resolves/creates an IAM
`Identity` and only then mints IAM's own JWT via `jwtsign.Signer`.

## Current state (as of 2026-08-16)

Phase 1 of the roadmap (§20 of the architecture plan) — core login,
single provider, end-to-end — is implemented and smoke-tested:

- `GET /login?provider=&app_id=&return_to=` — validates `return_to`
  against the app's configured allowed origins, generates PKCE
  verifier/challenge + opaque state, redirects to Supabase.
- `GET /callback?code=&iam_state=` — resolves state, exchanges the code,
  resolves/creates/merges the `Identity` (auto-merge only on
  verified-email match — see architecture plan §22 decision #1),
  redirects to the app with a short-lived opaque exchange code.
- `POST /token {"code": "..."}` — server-to-server exchange of that
  opaque code for the IAM's own signed JWT.
- `GET /.well-known/jwks.json` — public key publication so applications
  verify tokens locally, no callback to IAM on the hot path.
- `GET /healthz` — liveness probe.

Not yet built (see roadmap phases 2–7 in the architecture plan):
sessions/refresh tokens (Postgres + Redis), remaining SSO providers
beyond Google, custom login UI, admin module, Postgres adapter (identity
repo is in-memory only right now), hardening, SDK/docs rollout.

No tests exist yet. No CI. No Dockerfile/deploy config yet.

## Running locally

Requires env vars: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `IAM_CALLBACK_URL`,
`JWT_PRIVATE_KEY` (generate with `go run ./cmd/genkey`), optionally
`IAM_PORT` (default 8080), `PROVIDERS_ENABLED` (default `google`),
`IAM_ALLOWED_APPS` (JSON, e.g.
`{"demo":{"redirect_origins":["http://localhost:3000"]}}`).

```
cd iam
go run ./cmd/genkey            # copy JWT_PRIVATE_KEY out
go run ./cmd/server
```

## Non-goals (explicit, per PRD §17 / architecture plan §21)

Do not add: roles/permissions, MFA, org/team support, API key issuance,
OAuth client-management UI, consent management, audit-log feature,
billing, notifications, avatar management, last-login tracking, or any
business/application-specific data. Apple Sign-In is intentionally
excluded — not even representable in `domain/provider`.

## Conventions

- Ports (interfaces) live in `application/ports/{inbound,outbound}`;
  never import a concrete adapter from `application` or `domain`.
- Provider slugs in `domain/provider.Name` must match Supabase's exact
  dashboard slugs (e.g. Microsoft is `azure`, Meta is `facebook`, X is
  `twitter`) — verify against the Supabase project before enabling.
- New SSO provider = one small normalizer + one registry entry, no
  changes to use cases or handlers (architecture plan §8).
