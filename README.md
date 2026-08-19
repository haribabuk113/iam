# IAM — local testing guide

One repo, one `docker-compose.yml`, one shared Postgres instance, and the
IAM server itself:

- **`db`** (port 5432) — one Postgres instance, two schemas:
  - `auth` — GoTrue's own tables (raw provider identities, sessions,
    refresh tokens), owned by the `supabase_auth_admin` role. IAM never
    reads this directly.
  - `iam` — IAM's own identity store
    (`internal/adapters/outbound/postgres`), owned by the `iam` role.
    Owns IAM's normalized `identities` — the deduped/merged records IAM's
    own JWTs are signed from. Applied automatically at startup via
    versioned migrations (`internal/adapters/outbound/postgres/migrations`)
    — no manual `psql` step.

  Each role's `search_path` is set to its own schema at creation time
  (`scripts/db-init.sh`), so GoTrue and IAM only ever see their own
  tables even though they share one running Postgres process — the same
  shape upstream Supabase itself uses (`auth`/`public`/`storage`/... all
  in one database), not two separate database servers.
- **`iam-server`** (port 8080) — this service. Runs as a container in
  `docker-compose.yml` like everything else; `go run ./cmd/server` is
  still there as a faster inner loop for local debugging (see below).

The schema split is the architecture's core invariant made physical: IAM
never forwards a Supabase-issued token to an app. It resolves a GoTrue
identity into its own `Identity`, then mints its own JWT. Flattening both
into one schema would let GoTrue's tables and IAM's collide by name and
blur that boundary — two schemas in one Postgres instance keeps the
separation without needing two database servers to enforce it.

## 1. Start the whole stack

```
cp .env.sample .env   # fill in the values below

go run ./cmd/genkey    # copy the JWT_PRIVATE_KEY block into .env — iam-server won't boot without it
```

`.env` needs, at minimum:

```
POSTGRES_PASSWORD=<anything>
AUTH_DB_USER=supabase_auth_admin
AUTH_DB_PASSWORD=<anything>
IAM_DB_PASSWORD=<anything>
GOTRUE_JWT_SECRET=<anything, 32+ chars>
GOOGLE_CLIENT_ID=       # see "Testing Google sign-in" below — optional
GOOGLE_CLIENT_SECRET=   # optional

SUPABASE_ANON_KEY=local-dev-placeholder      # ignored by raw self-hosted GoTrue, any non-empty value works
IAM_CALLBACK_URL=http://localhost:8080/callback
JWT_PRIVATE_KEY=<paste from genkey, \n for newlines>
IAM_ALLOWED_APPS={"demo":{"redirect_origins":["http://localhost:3000"]}}
```

`DATABASE_URL` in `.env.sample` needs `IAM_DB_PASSWORD` substituted into
it by hand (only used by the bare-metal `go run ./cmd/server` path below
— compose builds this connection string itself from the vars above).

Everything else in `.env.sample` has a documented default and can be left
as-is for local dev.

```
docker compose up -d
docker compose ps     # wait for db, gotrue, iam-server all healthy; db-init exited(0)
curl http://localhost:9999/health    # {"version":"...","name":"GoTrue",...}
curl http://localhost:8080/healthz   # {"status":"ok"}
```

That's the whole stack — Postgres, GoTrue, and IAM itself — from one
command.

`db-init` creates both GoTrue's and IAM's roles/schemas and sets each
one's search_path once, before either service's first connection — doing
it after GoTrue has started breaks its migration runner on restart, so
don't `ALTER ROLE` by hand against a running stack; edit
`scripts/db-init.sh` and recreate the `db-data` volume instead.

### Faster inner loop: running iam-server outside Docker

For hot-reload during development, stop the containerized `iam-server` and
run the binary directly against the same `db`/`gotrue` containers —
`.env`'s `SUPABASE_URL`/`DATABASE_URL` already point at their published
`localhost` ports for exactly this:

```
docker compose stop iam-server
go run ./cmd/server
```

## Testing without Google — email/password

Exercises the full pipeline (identity resolve/create, JWT signing, JWKS)
without needing any OAuth provider:

```
curl -X POST http://localhost:8080/signup -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpass123","full_name":"Test User"}'
```

`GOTRUE_MAILER_AUTOCONFIRM=true` in `docker-compose.yml` means signup
returns a token immediately — no email step. Response:
`{"status":"ok","access_token":"...","ecosystem_id":"..."}`.
(Production turns this off — see "Going to production" below.)

Sign in again with the same credentials:

```
curl -X POST http://localhost:8080/signin -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpass123"}'
```

## Testing Google sign-in without your own production secrets

Google OAuth still needs *some* real registered client — there's no way to
fake that leg — but a free, zero-billing dev client takes 5 minutes:

1. **console.cloud.google.com** → new project → APIs & Services → OAuth
   consent screen.
2. User type **External**, publishing status **Testing** (no verification,
   no billing needed). Add your own Google account as a test user.
3. Credentials → Create Credentials → **OAuth client ID** → **Web
   application**.
4. Authorized redirect URI: `http://localhost:9999/callback` — GoTrue's
   callback, not IAM's, since GoTrue is the one talking to Google.
5. Copy the client ID/secret into `.env`'s `GOOGLE_CLIENT_ID` /
   `GOOGLE_CLIENT_SECRET`, then:

```
docker compose up -d gotrue --force-recreate
curl http://localhost:9999/settings   # confirm "google":true
```

Then drive the flow from a browser (PKCE state can't be curled through a
redirect):

```
open "http://localhost:8080/login?provider=google&app_id=demo&return_to=http://localhost:3000/"
```

Real Google consent screen → GoTrue callback → IAM `/callback` → redirect
to `http://localhost:3000/?code=...`. Exchange that code server-to-server —
`app_id` must match the one the login started with, so a code intercepted
off a different app's redirect can't be redeemed here:

```
curl -X POST http://localhost:8080/token -H "Content-Type: application/json" \
  -d '{"code":"<code from the redirect URL>","app_id":"demo"}'
```

## Rate limiting

`/login`, `/signup`, and `/signin` are throttled per client IP (token
bucket, `IAM_RATE_LIMIT_RPS`/`IAM_RATE_LIMIT_BURST` in `.env`, defaults
1 req/s with a burst of 5). A `429 {"error":"rate_limited"}` past that
means the limiter is doing its job, not a bug. GoTrue's own
`GOTRUE_RATE_LIMIT_EMAIL_SENT` and `GOTRUE_PASSWORD_MIN_LENGTH` are set in
`docker-compose.yml` from the same `.env` file.

## Metrics

`GET /metrics` exposes Prometheus counters/histograms
(`iam_http_requests_total`, `iam_http_request_duration_seconds`) —
unauthenticated, same as GoTrue's own `/health`. Put it behind whatever
scrapes it, don't expose it publicly.

## Rotating the JWT signing key

`jwtsign.Signer` only ever signs with one key, but can publish more than
one in JWKS during a rotation window — see the doc comment on
`jwtsign.NewSigner` for the full step-by-step (new key published
alongside the old one via `JWT_JWKS_EXTRA_KEYS`, wait out the access-token
TTL, then cut over). Skipping the overlap window invalidates every
outstanding token the instant you deploy.

## Verifying the data

**IAM's identity store** (the record IAM's JWT actually came from) — the
`iam` role's `search_path` already points at the `iam` schema, so table
names stay unqualified:

```
docker exec -it $(docker compose ps -q db) psql -U iam -d postgres \
  -c "select id, full_name, email, primary_provider, status from identities;"
docker exec -it $(docker compose ps -q db) psql -U iam -d postgres \
  -c "select * from identity_providers;"
```

**GoTrue's own user record** (what it thinks it authenticated) — same
instance, `supabase_auth_admin`'s own schema:

```
docker exec -it $(docker compose ps -q db) psql -U supabase_auth_admin -d postgres \
  -c "select id, email, raw_app_meta_data->>'provider' as provider, created_at from auth.users;"
```

**The JWT itself** — decode without verifying, to eyeball claims:

```
echo '<access_token>' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

Expect `sub` to match `identities.id` (IAM's `ecosystem_id`), not GoTrue's
`auth.users.id` — those are deliberately different IDs.

**JWKS** (what an application would fetch to verify the JWT locally):

```
curl http://localhost:8080/.well-known/jwks.json
```

`kid` in the JWT header must match a `kid` in this response.

## Backups

Self-hosted Supabase ships with no built-in backup mechanism, so this repo
has its own. One dump covers everything — both schemas live in the same
`db` instance:

```
scripts/backup.sh                        # dumps db to ./backups/db_<stamp>.sql.gz
scripts/restore.sh ./backups/db_<stamp>.sql.gz
```

Run `backup.sh` on a schedule (cron/systemd timer) and copy `BACKUP_DIR`
off this host — the script only produces the dump, not offsite storage.
For point-in-time recovery instead of daily snapshots, look at WAL-G or
pgBackRest.

## Single instance only

The session store (PKCE state between `/login` and `/callback`, and the
`/callback`→`/token` exchange code) is in-process (`memstore`) — correct
only for exactly one `iam-server` instance, since the callback or `/token`
call has to land on the same process that started the flow. This repo
runs single-instance only; if that ever changes, swap `memstore` for a
shared backend (Redis, a database, etc.) behind the same
`outbound.LoginStateStore`/`ExchangeCodeStore` ports — nothing else in the
codebase needs to change.

## Going to production

`docker-compose.yml` is a local-dev stack: every service's port is bound
to `127.0.0.1`, GoTrue auto-confirms signups instead of sending real
email, and secrets come from a plaintext `.env`. `docker-compose.prod.yml`
is a separate, standalone file (not an override — see the comment at its
top) for an actual deployment:

```
docker compose -f docker-compose.prod.yml up -d
```

What it changes, and what you need to provide in `.env` beyond the local
vars above:

- **No public database or GoTrue ports.** `db`, `gotrue`, and
  `iam-server` publish nothing to the host — `caddy` is the only public
  entry point.
- **TLS via Caddy**, automatic (Let's Encrypt) for two subdomains —
  `AUTH_DOMAIN` (→ `gotrue`) and `IAM_DOMAIN` (→ `iam-server`). Two
  subdomains rather than one path-split domain because the browser has to
  reach GoTrue directly (its `/authorize` entry point and its own
  OAuth-provider callback), not just IAM — see the `Caddyfile`. Point both
  domains' DNS at this host before starting the stack, or Caddy's
  certificate issuance will fail.
- **Real email.** `GOTRUE_MAILER_AUTOCONFIRM` is off; set
  `GOTRUE_SMTP_ADMIN_EMAIL`/`_HOST`/`_PORT`/`_USER`/`_PASS` to a real SMTP
  provider or confirmation/reset email has nowhere to go.
- **`SITE_URL`, `GOTRUE_URI_ALLOW_LIST`** — your actual application origin
  and its allowed `return_to` values.

`POSTGRES_PASSWORD`, `AUTH_DB_PASSWORD`, and `IAM_DB_PASSWORD` all matter
even more here than in dev — same shared Postgres instance, same
`db-init.sh` role/schema split, just with real secrets instead of
`openssl rand -hex` placeholders.

None of this changes what's in the local `.env.sample` vars from earlier —
it's additive, all listed in the "Production only" section at the bottom
of `.env.sample`.

## Resetting everything

```
docker compose down -v          # wipes db (local stack)
docker compose -f docker-compose.prod.yml down -v   # same, for the prod stack
```
