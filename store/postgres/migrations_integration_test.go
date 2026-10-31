//go:build integration

package postgres

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestMigrationsMatchSchema replays migrations/ into an empty database and
// fails unless the result equals schema.hcl. Instances only ever run
// migrations/, so a schema.hcl edit without a generated migration would
// otherwise reach a release unnoticed.
func TestMigrationsMatchSchema(t *testing.T) {
	ctx := context.Background()

	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(currentFile), "..", "..")

	container, err := tcpostgres.Run(ctx,
		"postgres:17-alpine",
		tcpostgres.WithDatabase("psina"),
		tcpostgres.WithUsername("psina"),
		tcpostgres.WithPassword("password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	dbURL, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// Same flags as the migrate service and make migrate-apply.
	out, err := exec.Command("atlas", "migrate", "apply",
		"--url", dbURL,
		"--dir", "file://"+filepath.Join(root, "migrations"),
		"--revisions-schema", "atlas",
	).CombinedOutput()
	require.NoError(t, err, "atlas migrate apply:\n%s", out)

	// search_path=public keeps the atlas revisions schema out of the comparison.
	out, err = exec.Command("atlas", "schema", "diff",
		"--from", dbURL+"&search_path=public",
		"--to", "file://"+filepath.Join(root, "schema.hcl"),
		"--dev-url", "docker://postgres/17/dev?search_path=public",
	).CombinedOutput()
	require.NoError(t, err, "atlas schema diff:\n%s", out)
	require.True(t, strings.Contains(string(out), "Schemas are synced"),
		"migrations/ does not reproduce schema.hcl; run make migrate-diff name=<what_changed>:\n%s", out)
}
