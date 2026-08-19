# IAM — local testing guide

One repo, one `docker-compose.yml`, two Postgres databases:

- **`auth-db`** (port 5433) — GoTrue's own database. Owns the `auth`
  schema: raw provider identities, sessions, refresh tokens. IAM never
  reads this directly.
- **`iam-db`** (port 5434) — IAM's own identity store
  (`internal/adapters/outbound/postgres`, schema in `schema.sql`). Owns
  IAM's normalized `identities` — the deduped/merged records IAM's own
  JWTs are signed from.

This split is the architecture's core invariant made physical: IAM never
forwards a Supabase-issued token to an app. It resolves a GoTrue identity
into its own `Identity`, then mints its own JWT. Merging the two DBs would
leak GoTrue's schema into IAM's domain. They're two databases in one
compose file (not two repos) purely so a fresh clone can stand the whole
thing up with one `docker compose up`.

## 1. Start the whole stack and generate a signing key

```
cp .env.sample .env   # fill in the values below
docker compose up -d
docker compose ps     # wait for auth-db and iam-db healthy, auth-db-init exited(0)
curl http://localhost:9999/health   # {"version":"...","name":"GoTrue",...}

go run ./cmd/genkey   # copy the JWT_PRIVATE_KEY block out
```

`.env` needs, in addition to the IAM vars below:

```
POSTGRES_PASSWORD=<anything>
AUTH_DB_USER=supabase_auth_admin
AUTH_DB_PASSWORD=<anything>
AUTH_DB_NAME=auth
GOTRUE_JWT_SECRET=<anything, 32+ chars>
GOOGLE_CLIENT_ID=       # see "Testing Google sign-in" below — optional
GOOGLE_CLIENT_SECRET=   # optional
```

`auth-db-init` sets GoTrue's role/schema/search_path once, before GoTrue's
first connection — doing it after GoTrue has started breaks its migration
runner on restart, so don't `ALTER ROLE` by hand against a running stack;
edit `scripts/auth-db-init.sh` and recreate the volume instead.

## 2. Configure and run IAM

The rest of `.env` (same file as above):

```
SUPABASE_URL=http://localhost:9999          # this stack's GoTrue, no /auth/v1 prefix
SUPABASE_ANON_KEY=local-dev-placeholder      # ignored by raw self-hosted GoTrue, any non-empty value works
DATABASE_URL=postgresql://iam:iam@localhost:5434/iam?sslmode=disable
IAM_CALLBACK_URL=http://localhost:8080/callback
JWT_PRIVATE_KEY=<paste from genkey, \n for newlines>
IAM_ALLOWED_APPS={"demo":{"redirect_origins":["http://localhost:3000"]}}
```

```
go run ./cmd/server
curl http://localhost:8080/healthz   # {"status":"ok"}
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
to `http://localhost:3000/?code=...`. Exchange that code server-to-server:

```
curl -X POST http://localhost:8080/token -H "Content-Type: application/json" \
  -d '{"code":"<code from the redirect URL>"}'
```

## Verifying the data

**IAM's identity store** (the record IAM's JWT actually came from):

```
docker exec -it $(docker compose ps -q iam-db) psql -U iam -d iam \
  -c "select id, full_name, email, primary_provider, status from identities;"
docker exec -it $(docker compose ps -q iam-db) psql -U iam -d iam \
  -c "select * from identity_providers;"
```

**GoTrue's own user record** (what it thinks it authenticated):

```
docker exec -it $(docker compose ps -q auth-db) psql -U supabase_auth_admin -d auth \
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

## Resetting everything

```
docker compose down -v   # wipes both auth-db and iam-db
```
