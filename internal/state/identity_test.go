package state_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikenorgate/discovery-bridge/internal/state"
)

func TestIdentityPersistenceAndCollision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "identities.db")
	store, err := state.Open(ctx, path, "db-")
	if err != nil {
		t.Fatal(err)
	}
	id, alias, err := store.Alias(ctx, "lan-a", "Sensor.LOCAL.", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 64 || !strings.HasPrefix(alias, "db-") {
		t.Fatalf("unexpected identity: %s %s", id, alias)
	}
	_, same, err := store.Alias(ctx, "lan-a", "sensor.local.", false)
	if err != nil || same != alias {
		t.Fatal("canonical identity changed", err)
	}
	_, other, err := store.Alias(ctx, "lan-b", "sensor.local.", false)
	if err != nil || other == alias {
		t.Fatal("source identities merged", err)
	}
	_, rotated, err := store.Alias(ctx, "lan-a", "sensor.local.", true)
	if err != nil || rotated == alias {
		t.Fatal("collision did not rotate alias", err)
	}
	if owned, err := store.Owns(ctx, alias); err != nil || !owned {
		t.Fatal("old reservation was released", err)
	}
	if source, name, err := store.Original(ctx, rotated); err != nil || source != "lan-a" || name != "sensor.local." {
		t.Fatalf("original identity: %s %s %v", source, name, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(ctx, path, "new-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	_, after, err := store.Alias(ctx, "lan-a", "sensor.local.", false)
	if err != nil || after != rotated {
		t.Fatal("restart or configured prefix changed an existing alias", err)
	}
}

func TestPythonReopensGoState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "identities.db")
	store, err := state.Open(ctx, path, "db-")
	if err != nil {
		t.Fatal(err)
	}
	id, alias, err := store.Alias(ctx, "lan-a", "sensor.local.", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	script := `import sqlite3,hashlib,sys
db=sqlite3.connect(sys.argv[1])
wire=b'\x06sensor\x05local\x00'
identity=hashlib.sha256(b'lan-a\x00'+wire).hexdigest()
row=db.execute('SELECT identity,source,original,alias,collision FROM identities').fetchone()
assert row==(identity,'lan-a',wire,sys.argv[3],0), row
assert identity==sys.argv[2]
suffix=hashlib.sha256((identity+':0').encode()).hexdigest()[:20]
assert row[3]=='db-'+suffix+'.local.'
assert db.execute('PRAGMA journal_mode').fetchone()[0]=='wal'
with db: db.execute('UPDATE identities SET collision=collision+1 WHERE identity=?',(identity,))
db.close()
`
	output, err := exec.CommandContext(ctx, "python3", "-c", script, path, id, alias).CombinedOutput()
	if err != nil {
		t.Fatalf("Python SQLite interoperability failed: %v: %s", err, output)
	}
	store, err = state.Open(ctx, path, "db-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	_, same, err := store.Alias(ctx, "lan-a", "sensor.local.", false)
	if err != nil || same != alias {
		t.Fatal("Python write broke Go state", err)
	}
}
