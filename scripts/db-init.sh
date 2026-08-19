#!/usr/bin/env bash
# One-shot init for the shared `db` service: creates both GoTrue's and
# IAM's roles/schemas and sets each role's search_path BEFORE either
# service ever connects. Doing this after GoTrue has started/migrated
# breaks its migration runner on restart — confirmed by reproducing the
# crash on both v2.189.0 and v2.195.0 (see README) — so don't run this
# SQL by hand against a running stack; edit this script and recreate the
# `db-data` volume instead.
#
# One Postgres instance, two schemas — auth (GoTrue) and iam (this
# service) — each owned by its own least-privilege role, same shape
# upstream Supabase itself uses (auth/public/storage/... schemas sharing
# one database). Not one flat schema: keeps GoTrue's internal tables and
# IAM's identities from ever colliding on a name, and keeps each role
# unable to touch the other's tables.
set -euo pipefail

psql "postgresql://postgres:${PGPASSWORD}@db:5432/${POSTGRES_DB}" -v ON_ERROR_STOP=1 <<-SQL
	DO \$\$
	BEGIN
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${AUTH_DB_USER}') THEN
	    CREATE ROLE ${AUTH_DB_USER} WITH LOGIN PASSWORD '${AUTH_DB_PASSWORD}' NOINHERIT;
	  END IF;
	END
	\$\$;

	CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION ${AUTH_DB_USER};
	GRANT ALL ON SCHEMA auth TO ${AUTH_DB_USER};
	ALTER ROLE ${AUTH_DB_USER} SET search_path TO auth, public;

	DO \$\$
	BEGIN
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${IAM_DB_USER}') THEN
	    CREATE ROLE ${IAM_DB_USER} WITH LOGIN PASSWORD '${IAM_DB_PASSWORD}' NOINHERIT;
	  END IF;
	END
	\$\$;

	CREATE SCHEMA IF NOT EXISTS iam AUTHORIZATION ${IAM_DB_USER};
	GRANT ALL ON SCHEMA iam TO ${IAM_DB_USER};
	ALTER ROLE ${IAM_DB_USER} SET search_path TO iam, public;
SQL
