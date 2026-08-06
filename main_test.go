package main

import (
	"bytes"
	"encoding/json"
	"testing"
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
