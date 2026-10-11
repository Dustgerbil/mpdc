package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

// These fixtures were captured from the source before the review changes.
// Round-tripping them catches renamed fields, changed types and lost evidence.
func TestSchemaV2LegacyFixtures(t *testing.T) {
	for _, name := range []string{"minimal", "complete"} {
		t.Run(name, func(t *testing.T) {
			expected, err := os.ReadFile("testdata/schema-v2-" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var results []Result
			if err := json.Unmarshal(expected, &results); err != nil {
				t.Fatal(err)
			}
			actual, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytes.TrimSpace(expected), actual) {
				t.Fatalf("schema compatibility changed:\n%s", actual)
			}
		})
	}
}

func TestCompatibilityFields(t *testing.T) {
	issued := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	r := Result{Endpoints: []EndpointResult{{IP: "192.0.2.1", Error: "failed"}, {IP: "192.0.2.2", TLSVersion: "TLS 1.3", Certificate: &CertificateInfo{Subject: "CN=example.com", AltNames: []string{"example.com"}, Issuer: "CN=issuer", Issued: issued, Expiry: issued.Add(time.Hour)}}}}
	populateCompatibilityFields(&r)
	if r.Subject != "CN=example.com" || r.TLSVersion != "TLS 1.3" || r.Issuer != "CN=issuer" || !r.Issued.Equal(issued) || !reflect.DeepEqual(r.AltNames, []string{"example.com"}) || r.Error != "" {
		t.Fatalf("compatibility fields: %+v", r)
	}
	r.Endpoints[1].Certificate.AltNames[0] = "changed"
	if r.AltNames[0] != "example.com" {
		t.Fatal("compatibility aliases certificate slice")
	}
}
