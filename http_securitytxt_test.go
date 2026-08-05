package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityTXTParsing(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	page := HTTPPageResult{
		RequestedURL: "https://example.com/.well-known/security.txt",
		FinalURL:     "https://example.com/.well-known/security.txt",
		StatusCode:   200,
		ContentType:  "text/plain; charset=utf-8",
	}
	body := []byte("Contact: mailto:security@example.com\nExpires: 2031-01-01T00:00:00Z\nCanonical: https://example.com/.well-known/security.txt\nPolicy: https://example.com/policy\nEncryption: https://example.com/key.asc\nPreferred-Languages: en, fr\nExtension-Field: retained\n")
	result := parseSecurityTXTPage(page, body, now)
	if !result.Present || !result.UTF8Valid || len(result.Contacts) != 1 || len(result.UnknownFieldNames) != 1 || result.UnknownFieldNames[0] != "Extension-Field" {
		t.Fatalf("valid security.txt = %+v", result)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("valid security.txt findings = %+v", result.Findings)
	}
}

func TestSecurityTXTInvalidExpiredAndSigned(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	base := HTTPPageResult{
		RequestedURL: "https://example.com/.well-known/security.txt",
		FinalURL:     "https://example.com/.well-known/security.txt",
		StatusCode:   200,
		ContentType:  "application/octet-stream",
	}
	result := parseSecurityTXTPage(base, []byte("Contact: not-a-uri\nExpires: invalid\n"), now)
	assertFindingCode(t, result.Findings, "SECURITY_TXT_INVALID")

	base.ContentType = "text/plain"
	result = parseSecurityTXTPage(base, []byte("Contact: mailto:security@example.com\nExpires: 2029-01-01T00:00:00Z\n"), now)
	assertFindingCode(t, result.Findings, "SECURITY_TXT_EXPIRED")

	result = parseSecurityTXTPage(base, []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:security@example.com\nExpires: 2031-01-01T00:00:00Z\n-----BEGIN PGP SIGNATURE-----\n"), now)
	if !result.Signed {
		t.Fatal("cleartext signature was not observed")
	}
}

func TestSecurityTXTCanonicalHTTPSAndLanguageValidation(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	page := HTTPPageResult{
		RequestedURL: "https://example.com/.well-known/security.txt",
		FinalURL:     "https://example.com/.well-known/security.txt",
		finalURLRaw:  "https://example.com/.well-known/security.txt",
		StatusCode:   200,
		ContentType:  "text/plain",
	}
	valid := []byte("Contact: mailto:security@example.com\nExpires: 2031-01-01T00:00:00Z\nCanonical: https://EXAMPLE.com:443/.well-known/security.txt\nPreferred-Languages: en, zh-Hant-TW, de-CH-1901, x-private\n")
	result := parseSecurityTXTPage(page, valid, now)
	if len(result.Findings) != 0 || len(result.PreferredLanguages) != 4 {
		t.Fatalf("valid Canonical/languages result = %+v", result)
	}

	invalid := []byte("Contact: http://example.com/report\nExpires: 2031-01-01T00:00:00Z\nCanonical: https://example.com/security.txt\nPolicy: http://example.com/policy\nPreferred-Languages: en_US\nPreferred-Languages: en\n")
	result = parseSecurityTXTPage(page, invalid, now)
	assertFindingCode(t, result.Findings, "SECURITY_TXT_INVALID")
	message := result.Findings[len(result.Findings)-1].Message
	for _, expected := range []string{"web URIs must use HTTPS", "absent from Canonical", "Preferred-Languages", "RFC 5646"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("invalid finding did not mention %q: %s", expected, message)
		}
	}
}

func TestSecurityTXTCanonicalUsesRawURLButRedactsOutput(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	page := HTTPPageResult{
		RequestedURL: "https://example.com/.well-known/security.txt",
		FinalURL:     "https://example.com/.well-known/security.txt?token=[redacted]",
		finalURLRaw:  "https://example.com/.well-known/security.txt?token=secret-token",
		StatusCode:   200,
		ContentType:  "text/plain",
	}
	body := []byte("Contact: mailto:security@example.com\nExpires: 2031-01-01T00:00:00Z\nCanonical: https://example.com/.well-known/security.txt?token=secret-token\n")
	result := parseSecurityTXTPage(page, body, now)
	if len(result.Findings) != 0 {
		t.Fatalf("matching raw Canonical findings = %+v", result.Findings)
	}
	if len(result.Canonical) != 1 || strings.Contains(result.Canonical[0], "secret-token") || !strings.Contains(result.Canonical[0], "token=[redacted]") {
		t.Fatalf("Canonical output was not redacted: %+v", result.Canonical)
	}
}

func TestSecurityTXTMissingAndLegacy(t *testing.T) {
	missing := parseSecurityTXTPage(HTTPPageResult{
		RequestedURL: "https://example.com/.well-known/security.txt",
		FinalURL:     "https://example.com/.well-known/security.txt",
		StatusCode:   404,
	}, nil, time.Now())
	if missing.Present {
		t.Fatal("404 security.txt marked present")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/.well-known/security.txt" {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		response.Header().Set("Content-Type", "text/plain")
		_, _ = response.Write([]byte("Contact: mailto:security@example.com\nExpires: 2031-01-01T00:00:00Z\n"))
	}))
	defer server.Close()
	dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
	scanner := testScanner(defaultHTTPOptions(), dialer)
	legacy := scanner.inspectSecurityTXT("example.com", map[string]bool{"example.com": true})
	if !legacy.Present || legacy.RequestedURL != "https://example.com/security.txt" {
		t.Fatalf("legacy result = %+v", legacy)
	}
	assertFindingCode(t, legacy.Findings, "SECURITY_TXT_LEGACY_LOCATION")
}

func TestSecurityTXTInsecureRedirect(t *testing.T) {
	page := HTTPPageResult{
		RequestedURL:  "https://example.com/.well-known/security.txt",
		FinalURL:      "https://example.com/.well-known/security.txt",
		Findings:      []Finding{finding("HTTP_REDIRECT_TO_INSECURE", "critical", "downgrade")},
		RedirectChain: []RedirectHop{{ResolvedURL: "http://example.com/security.txt"}},
	}
	result := parseSecurityTXTPage(page, nil, time.Now())
	assertFindingCode(t, result.Findings, "SECURITY_TXT_INSECURE_REDIRECT")
}
