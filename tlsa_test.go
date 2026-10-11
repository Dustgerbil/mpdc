package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
)

func testTLSA(cert *x509.Certificate) TLSARecord {
	sum := sha256.Sum256(cert.Raw)
	return TLSARecord{CertificateUsage: 3, Selector: 0, MatchingType: 1, AssociationData: hex.EncodeToString(sum[:]), DNSSECValidated: true}
}

func TestTLSAEndpointFindings(t *testing.T) {
	good := &x509.Certificate{Raw: []byte("good")}
	bad := &x509.Certificate{Raw: []byte("bad")}
	for _, tc := range []struct {
		name       string
		certs      []*x509.Certificate
		want       []string
		mismatches int
	}{
		{"all match", []*x509.Certificate{good, good}, []string{"matched", "matched"}, 0},
		{"one mismatch", []*x509.Certificate{good, bad}, []string{"matched", "mismatched"}, 1},
		{"all mismatch", []*x509.Certificate{bad, bad}, []string{"mismatched", "mismatched"}, 2},
		{"unavailable", []*x509.Certificate{nil}, []string{"unavailable"}, 0},
		{"no endpoints", nil, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Result{DNS: DNSDetails{TLSA: []TLSARecord{testTLSA(good)}}}
			for i, cert := range tc.certs {
				e := EndpointResult{IP: []string{"192.0.2.1", "192.0.2.2"}[i]}
				if cert != nil {
					e.peerCertificates = []*x509.Certificate{cert}
				}
				r.Endpoints = append(r.Endpoints, e)
			}
			addDNSFindings(&r)
			count := 0
			for _, f := range r.Findings {
				if f.Code == "DANE_TLSA_MISMATCH" {
					count++
				}
			}
			if count != tc.mismatches {
				t.Fatalf("mismatches = %d: %+v", count, r.Findings)
			}
			for i, e := range r.Endpoints {
				if e.TLSAStatus != tc.want[i] {
					t.Errorf("endpoint %d: %s", i, e.TLSAStatus)
				}
				if e.TLSAStatus == "mismatched" && (len(e.Findings) != 1 || !strings.Contains(e.Findings[0].Message, e.IP)) {
					t.Errorf("missing endpoint evidence: %+v", e)
				}
			}
			if tc.name == "unavailable" || tc.name == "no endpoints" {
				assertFindingCode(t, r.Findings, "DANE_TLSA_UNAVAILABLE")
			}
		})
	}
	// A rotation may publish several valid associations: each endpoint needs any one.
	r := Result{DNS: DNSDetails{TLSA: []TLSARecord{testTLSA(good), testTLSA(bad)}}, Endpoints: []EndpointResult{{peerCertificates: []*x509.Certificate{good}}, {peerCertificates: []*x509.Certificate{bad}}}}
	addDNSFindings(&r)
	if len(r.Findings) != 0 {
		t.Fatalf("rotation: %+v", r.Findings)
	}
}

func TestTLSAUnsupportedAndUnauthenticated(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("certificate")}
	for _, tc := range []struct {
		name   string
		modify func(*TLSARecord)
		code   string
	}{
		{"unauthenticated", func(r *TLSARecord) { r.DNSSECValidated = false }, "DANE_TLSA_NOT_VALIDATED"},
		{"usage", func(r *TLSARecord) { r.CertificateUsage = 4 }, "DANE_TLSA_UNAVAILABLE"},
		{"selector", func(r *TLSARecord) { r.Selector = 2 }, "DANE_TLSA_UNAVAILABLE"},
		{"matching", func(r *TLSARecord) { r.MatchingType = 3 }, "DANE_TLSA_UNAVAILABLE"},
		{"short digest", func(r *TLSARecord) { r.AssociationData = "ab" }, "DANE_TLSA_UNAVAILABLE"},
		{"bad hex", func(r *TLSARecord) { r.AssociationData = "zz" }, "DANE_TLSA_UNAVAILABLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := testTLSA(cert)
			tc.modify(&record)
			r := Result{DNS: DNSDetails{TLSA: []TLSARecord{record}}, Endpoints: []EndpointResult{{peerCertificates: []*x509.Certificate{cert}}}}
			addDNSFindings(&r)
			if len(r.Findings) != 1 || r.Findings[0].Code != tc.code {
				t.Fatalf("%+v", r.Findings)
			}
		})
	}
}

func TestTLSAMatchingForms(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("certificate"), RawSubjectPublicKeyInfo: []byte("key")}
	for selector := uint8(0); selector < 2; selector++ {
		for matching := uint8(0); matching < 3; matching++ {
			value := cert.Raw
			if selector == 1 {
				value = cert.RawSubjectPublicKeyInfo
			}
			switch matching {
			case 1:
				sum := sha256.Sum256(value)
				value = sum[:]
			case 2:
				sum := sha512.Sum512(value)
				value = sum[:]
			}
			r := TLSARecord{CertificateUsage: 3, Selector: selector, MatchingType: matching, AssociationData: hex.EncodeToString(value)}
			if !tlsaMatchesEndpoints(r, []EndpointResult{{peerCertificates: []*x509.Certificate{cert}}}) {
				t.Fatalf("selector %d, matching %d", selector, matching)
			}
		}
	}
}
