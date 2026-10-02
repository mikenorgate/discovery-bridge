//go:build reference && linux

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/responder"
)

func TestGoClientWithPythonRouter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, "python3", "../../tests/reference_gateway.py", filepath.Join(t.TempDir(), "generation.sqlite"))
	source, err := filepath.Abs("../../reference/python")
	if err != nil {
		t.Fatal(err)
	}
	command.Env = append(os.Environ(), "PYTHONPATH="+source, "PYTHONDONTWRITEBYTECODE=1")
	command.Stderr = os.Stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stdin.Close(); err != nil {
			t.Error(err)
		}
		if err := command.Wait(); err != nil {
			t.Error(err)
		}
	})
	reader := bufio.NewScanner(stdout)
	read := func(value any) {
		t.Helper()
		if !reader.Scan() {
			t.Fatal("Python router did not reply", reader.Err())
		}
		if err := json.Unmarshal(reader.Bytes(), value); err != nil {
			t.Fatal(err)
		}
	}
	var ready struct{ Port int }
	read(&ready)
	client, err := NewClient(config.Endpoint{Host: "127.0.0.1", Port: ready.Port})
	if err != nil {
		t.Fatal(err)
	}
	node := catalog.NewNodeFeed(testPolicy(t), nil)
	if _, err := client.Refresh(ctx, node); err != nil {
		t.Fatal(err)
	}
	view := node.View(catalog.Now())
	if len(view) != 6 {
		t.Fatal("Python DNS-SD chain was not preserved", view)
	}
	for _, answer := range view {
		if txt, ok := answer.RR.(*dns.TXT); ok {
			message := dns.Msg{Answer: []dns.RR{txt}}
			wire, err := message.Pack()
			if err != nil || !bytes.Contains(wire, []byte("opaque=\xff\x00")) || !answer.Unique {
				t.Fatal("opaque TXT or ownership changed", answer, err)
			}
		}
	}
	value, err := (responder.Query{Questions: []responder.Question{{Name: "missing.local.", Type: dns.TypeAAAA, Class: 1}}}).Lookup()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.Post(ctx, "/v1/lookup", data, 202); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(stdin, "lookups\n"); err != nil {
		t.Fatal(err)
	}
	var lookups struct {
		Questions []responder.Question `json:"questions"`
	}
	read(&lookups)
	if len(lookups.Questions) != 1 || lookups.Questions[0].Name != "missing.local." || lookups.Questions[0].Type != dns.TypeAAAA {
		t.Fatal("Python gateway demand was not question-only or coalesced", lookups)
	}
	if _, err := client.Post(ctx, "/v1/publications", []byte(`{"schema":1}`), 200); err == nil {
		t.Fatal("Python node endpoint accepted publication")
	}
	if _, err := io.WriteString(stdin, "withdraw\n"); err != nil {
		t.Fatal(err)
	}
	var withdrawn struct{ Withdrawn bool }
	read(&withdrawn)
	if !withdrawn.Withdrawn {
		t.Fatal("Python withdrawal did not complete")
	}
	if _, err := client.Refresh(ctx, node); err != nil {
		t.Fatal(err)
	}
	if len(node.View(catalog.Now())) != 0 {
		t.Fatal("withdrawn Python records survived Go refresh")
	}
}
