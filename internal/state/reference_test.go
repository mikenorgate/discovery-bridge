//go:build reference && linux

package state_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

func TestAliasesAndSQLiteMatchPythonReference(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pythonPath, goPath := filepath.Join(t.TempDir(), "python.sqlite"), filepath.Join(t.TempDir(), "go.sqlite")
	source, err := filepath.Abs("../../reference/python")
	if err != nil {
		t.Fatal(err)
	}
	python := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, "python3", append([]string{"../../tests/reference_identities.py"}, args...)...)
		command.Env = append(os.Environ(), "PYTHONPATH="+source, "PYTHONDONTWRITEBYTECODE=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("Python identity reference: %v: %s", err, output)
		}
		return output
	}
	var operations []struct {
		Op, Source, Name, Identity string
		AliasWire                  string `json:"alias_wire"`
	}
	if err := json.Unmarshal(python("create", pythonPath), &operations); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, goPath, "db-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for _, operation := range operations {
		var id, alias string
		if operation.Op == "alias" {
			id, alias, err = store.Alias(ctx, operation.Source, operation.Name, false)
		} else {
			alias, err = store.RotateAlias(ctx, operation.Name)
		}
		if err != nil || id != operation.Identity {
			t.Fatal("identity differs from Python", operation, id, err)
		}
		wire := make([]byte, 256)
		n, err := dns.PackDomainName(alias, wire, 0, nil, false)
		if err != nil || hex.EncodeToString(wire[:n]) != operation.AliasWire {
			t.Fatal("alias differs from Python", operation.Name, alias, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	python("compare", pythonPath, goPath)
}
