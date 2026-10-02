package state

import (
	"context"
	"path/filepath"
	"testing"
)

func TestGenerationOwnerLockAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generation.sqlite")
	g, err := OpenGeneration(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if g.Number != 1 {
		t.Fatal(g.Number)
	}
	if other, err := OpenGeneration(context.Background(), path); err == nil {
		if err := other.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("second gateway owner admitted")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g, err = OpenGeneration(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if g.Number != 2 {
		t.Fatal(g.Number)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
}
