#!/usr/bin/env bash
# One-shot init for the auth-db service: creates the GoTrue role/schema and
# sets search_path BEFORE GoTrue ever connects. Doing this after GoTrue has
# started/migrated breaks its migration runner on restart — confirmed by
# reproducing the crash on both v2.189.0 and v2.195.0 (see README).
set -euo pipefail

psql "postgresql://postgres:${PGPASSWORD}@auth-db:5432/${AUTH_DB_NAME}" -v ON_ERROR_STOP=1 <<-SQL
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
SQL
