package state_test

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

func TestAliasAndSQLiteFixtures(t *testing.T) {
	ctx := context.Background()
	data, err := os.ReadFile("../../tests/fixtures/identities.json")
	if err != nil {
		t.Fatal(err)
	}
	var operations []struct {
		Op, Source, Name, Identity string
		AliasWire                  string `json:"alias_wire"`
	}
	if err := json.Unmarshal(data, &operations); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identities.db")
	store, err := state.Open(ctx, path, "db-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	nameWire := func(name string) string {
		t.Helper()
		wire := make([]byte, 256)
		n, err := dns.PackDomainName(name, wire, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(wire[:n])
	}
	for _, operation := range operations {
		var id, alias string
		if operation.Op == "alias" {
			id, alias, err = store.Alias(ctx, operation.Source, operation.Name, false)
		} else {
			alias, err = store.RotateAlias(ctx, operation.Name)
		}
		if err != nil || id != operation.Identity || nameWire(alias) != operation.AliasWire {
			t.Fatal("identity or alias differs from fixture", operation, id, alias, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("../../tests/fixtures/identity-state.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Identities   [][]any
		Reservations [][]string
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	for _, row := range expected.Identities {
		row[3] = nameWire(row[3].(string))
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	rows, err := db.QueryContext(ctx, "SELECT identity,source,lower(hex(original)),alias,collision FROM identities ORDER BY identity")
	if err != nil {
		t.Fatal(err)
	}
	var identities [][]any
	for rows.Next() {
		var id, source, original, alias string
		var collision int
		if err := rows.Scan(&id, &source, &original, &alias, &collision); err != nil {
			t.Fatal(err)
		}
		identities = append(identities, []any{id, source, original, nameWire(alias), float64(collision)})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err = db.QueryContext(ctx, "SELECT lower(hex(name)),identity FROM reservations ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var reservations [][]string
	for rows.Next() {
		var name, id string
		if err := rows.Scan(&name, &id); err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, []string{name, id})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(identities, expected.Identities) || !reflect.DeepEqual(reservations, expected.Reservations) {
		t.Fatal("persistent identities or reservations differ from fixture", identities, reservations)
	}
}
