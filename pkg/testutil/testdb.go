//go:build integration

package testutil

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestDB wraps a postgres testcontainer with a connection pool.
type TestDB struct {
	Pool      *pgxpool.Pool
	container *postgres.PostgresContainer
}

// NewTestDB starts a postgres container and returns a TestDB.
// Call Close() when done (typically in TestMain).
func NewTestDB(ctx context.Context) (*TestDB, error) {
	container, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase("psina"),
		postgres.WithUsername("psina"),
		postgres.WithPassword("password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("start postgres container: %w", err)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("get connection string: %w", err)
	}

	// Apply schema using Atlas CLI
	if err := applySchema(connStr); err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("create pool: %w", err)
	}

	return &TestDB{
		Pool:      pool,
		container: container,
	}, nil
}

// applySchema runs atlas schema apply against the database.
func applySchema(dbURL string) error {
	// Get path to schema.hcl
	_, currentFile, _, _ := runtime.Caller(0)
	schemaPath := filepath.Join(filepath.Dir(currentFile), "..", "..", "schema.hcl")

	cmd := exec.Command("atlas", "schema", "apply",
		"--url", dbURL,
		"--to", fmt.Sprintf("file://%s", schemaPath),
		"--dev-url", "docker://postgres/17/dev?search_path=public",
		"--auto-approve",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("atlas schema apply failed: %w\noutput: %s", err, output)
	}

	return nil
}

// Close terminates the container and closes the pool.
func (db *TestDB) Close(ctx context.Context) {
	if db.Pool != nil {
		db.Pool.Close()
	}
	if db.container != nil {
		_ = db.container.Terminate(ctx)
	}
}

// Truncate clears all tables for test isolation.
func (db *TestDB) Truncate(ctx context.Context) error {
	_, err := db.Pool.Exec(ctx, `
		TRUNCATE TABLE refresh_tokens, local_credentials, users CASCADE
	`)
	return err
}

// MustTruncate is like Truncate but fails the test on error.
func (db *TestDB) MustTruncate(t *testing.T) {
	t.Helper()
	if err := db.Truncate(context.Background()); err != nil {
		t.Fatalf("failed to truncate tables: %v", err)
	}
}
