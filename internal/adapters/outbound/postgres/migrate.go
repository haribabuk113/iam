package postgres

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"

	// registers the "pgx" database/sql driver goose needs — the app's own
	// runtime path uses pgxpool directly (see New()), this is only for
	// goose's migration runner, which speaks database/sql.
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies every pending migration in migrations/ — replacing the
// old "apply schema.sql by hand before running the server" step so a
// fresh deploy never needs a manual psql session, and schema changes have
// a versioned, repeatable history instead of one mutable file.
func Migrate(connString string) error {
	db, err := sql.Open("pgx", connString)
	if err != nil {
		return fmt.Errorf("postgres: open for migration: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("postgres: set migration dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("postgres: run migrations: %w", err)
	}
	return nil
}
