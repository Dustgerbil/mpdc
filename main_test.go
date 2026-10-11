package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteSchemaCapabilities(t *testing.T) {
	var output bytes.Buffer
	if err := writeSchemaCapabilities(&output); err != nil {
		t.Fatal(err)
	}

	var got SchemaCapabilities
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("schema capabilities are not valid JSON: %v", err)
	}
	if got.SchemaVersion != jsonSchemaVersion {
		t.Fatalf("schema version = %d, want %d", got.SchemaVersion, jsonSchemaVersion)
	}

	want := []SchemaCapability{
		{Name: "dns", EnabledByDefault: true},
		{Name: "tls", EnabledByDefault: true},
		{Name: "mail", Flag: "-mail"},
		{Name: "http", Flag: "-http"},
	}
	if len(got.Capabilities) != len(want) {
		t.Fatalf("capability count = %d, want %d", len(got.Capabilities), len(want))
	}
	for i := range want {
		if got.Capabilities[i] != want[i] {
			t.Errorf("capability %d = %+v, want %+v", i, got.Capabilities[i], want[i])
		}
	}
}

func TestCLIValidationAndPreflight(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		code     int
		contains string
	}{
		{[]string{"-version"}, 0, "mpdc "},
		{[]string{"-schema-capabilities"}, 0, `"schema_version": 2`},
		{[]string{"-h"}, 0, "scan-timeout"},
		{[]string{"-bad-flag"}, 2, "flag provided but not defined"},
		{[]string{"-json", "-markdown"}, 1, "mutually exclusive"},
		{[]string{"-scan-timeout", "0"}, 1, "must be positive"},
		{[]string{"-concurrency", "0"}, 1, "between 1 and 64"},
		{[]string{"-concurrency", "65"}, 1, "between 1 and 64"},
		{[]string{"-http-timeout", "0"}, 1, "greater than zero"},
		{[]string{"-http-max-redirects", "51"}, 1, "between 0 and 50"},
		{[]string{"-http-max-body", "0"}, 1, "between 1"},
		{[]string{"-http-path", "//bad"}, 2, "invalid"},
		{nil, 1, "Usage:"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tc.args, nil, &stdout, &stderr, nil)
			if code != tc.code || !strings.Contains(stdout.String()+stderr.String(), tc.contains) {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIInputAndOutputModes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(file, []byte("file.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"-json", "-markdown", ""} {
		args := []string{"-file", file, "-dns-server", "127.0.0.1:53"}
		if mode != "" {
			args = append(args, mode)
		}
		args = append(args, "arg.example")
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, strings.NewReader("stdin.example\n"), &stdout, &stderr, fixtureHostScanner())
		if code != 0 {
			t.Fatalf("mode=%s code=%d stderr=%s", mode, code, stderr.String())
		}
		for _, host := range []string{"arg.example", "stdin.example", "file.example"} {
			if !strings.Contains(stdout.String(), host) {
				t.Errorf("missing %s in %s", host, stdout.String())
			}
		}
		if mode == "-json" {
			var results []Result
			if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
				t.Fatal(err)
			}
			if len(results) != 3 || results[0].Hostname != "arg.example" || results[1].Hostname != "stdin.example" || results[2].Hostname != "file.example" {
				t.Fatalf("ordering=%+v", results)
			}
		}
	}
}

func TestCLIInputCancellation(t *testing.T) {
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 1)
	reader := readFunc(func(p []byte) (int, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		return input.Read(p)
	})
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-json"}, reader, io.Discard, io.Discard, nil) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("reader did not start")
	}
	cancel()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit code = %d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for input ignored cancellation")
	}
}

type readFunc func([]byte) (int, error)

func (f readFunc) Read(p []byte) (int, error) { return f(p) }
