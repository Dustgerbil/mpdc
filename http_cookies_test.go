package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCookieObservationsAndRedaction(t *testing.T) {
	fields := []string{
		"session=super-secret; Secure; HttpOnly; SameSite=Lax; Path=/",
		"__Host-token=another-secret; Path=/; HttpOnly",
		"cross=value; SameSite=None",
	}
	cookies := observeCookies(fields)
	if len(cookies) != 3 {
		t.Fatalf("cookies = %+v", cookies)
	}
	if cookies[0].Name != "session" || !cookies[0].Secure || !cookies[0].HTTPOnly || cookies[0].SameSite != "Lax" {
		t.Fatalf("first cookie = %+v", cookies[0])
	}
	findings := evaluateCookieFindings("https://example.com/", cookies)
	assertFindingCode(t, findings, "COOKIE_SECURE_MISSING")
	assertFindingCode(t, findings, "COOKIE_HTTPONLY_MISSING")
	assertFindingCode(t, findings, "COOKIE_SAMESITE_MISSING")
	assertFindingCode(t, findings, "COOKIE_SAMESITE_NONE_WITHOUT_SECURE")
	assertFindingCode(t, findings, "COOKIE_PREFIX_INVALID")

	encoded, err := json.Marshal(cookies)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"super-secret", "another-secret", "cross=value"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("cookie value leaked: %s", encoded)
		}
	}
}

func TestValidCookiePrefixes(t *testing.T) {
	cookies := observeCookies([]string{
		"__Host-token=x; Secure; Path=/; HttpOnly; SameSite=Strict",
		"__Secure-token=y; Secure; HttpOnly; SameSite=Lax",
	})
	for _, item := range evaluateCookieFindings("https://example.com/", cookies) {
		if item.Code == "COOKIE_PREFIX_INVALID" {
			t.Fatalf("valid prefix flagged: %+v", item)
		}
	}
}
