package state_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

func TestSQLiteSchemaAndIndependentWriter(t *testing.T) {
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
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	wire := []byte("\x06sensor\x05local\x00")
	hash := sha256.Sum256(append([]byte("lan-a\x00"), wire...))
	expectedID := hex.EncodeToString(hash[:])
	suffix := sha256.Sum256([]byte(expectedID + ":0"))
	var storedID, source, storedAlias, journal string
	var original []byte
	var collision int
	if err := db.QueryRowContext(ctx, "SELECT identity,source,original,alias,collision FROM identities").Scan(&storedID, &source, &original, &storedAlias, &collision); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if storedID != expectedID || storedID != id || source != "lan-a" || !bytes.Equal(original, wire) || collision != 0 || storedAlias != alias || storedAlias != "db-"+hex.EncodeToString(suffix[:])[:20]+".local." || journal != "wal" {
		t.Fatal("SQLite schema or stable identity differs", storedID, source, original, storedAlias, collision, journal)
	}
	if _, err := db.ExecContext(ctx, "UPDATE identities SET collision=collision+1 WHERE identity=?", id); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
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
		t.Fatal("independent SQLite write broke identity state", err)
	}
}
