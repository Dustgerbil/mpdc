package main

import (
	"net/http"
	"reflect"
	"testing"
)

func TestHSTSFindings(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		code   string
	}{
		{name: "valid", values: []string{"max-age=31536000; includeSubDomains; preload"}},
		{name: "missing", code: "HSTS_MISSING"},
		{name: "invalid", values: []string{"includeSubDomains"}, code: "HSTS_INVALID"},
		{name: "duplicate fields", values: []string{"max-age=10", "max-age=20"}, code: "HSTS_INVALID"},
		{name: "duplicate directive", values: []string{"max-age=10; max-age=20"}, code: "HSTS_INVALID"},
		{name: "disabled", values: []string{"max-age=0"}, code: "HSTS_DISABLED"},
		{name: "short", values: []string{"max-age=300"}, code: "HSTS_SHORT_MAX_AGE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := evaluateHSTS("https://example.com/", test.values)
			if test.code == "" {
				if len(findings) != 0 {
					t.Fatalf("unexpected findings: %+v", findings)
				}
				return
			}
			assertFindingCode(t, findings, test.code)
		})
	}
}

func TestCSPPolicySemantics(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		assertFindingCode(t, evaluateCSP("https://example.com/", nil, nil), "CSP_MISSING")
	})
	t.Run("report only", func(t *testing.T) {
		assertFindingCode(t, evaluateCSP("https://example.com/", nil, []string{"default-src 'none'"}), "CSP_NOT_ENFORCED")
		findings := evaluateCSP("https://example.com/", nil, []string{""})
		assertFindingCode(t, findings, "CSP_INVALID")
		assertFindingCode(t, findings, "CSP_NOT_ENFORCED")
	})
	t.Run("invalid and empty", func(t *testing.T) {
		assertFindingCode(t, evaluateCSP("https://example.com/", []string{""}, nil), "CSP_INVALID")
		assertFindingCode(t, evaluateCSP("https://example.com/", []string{"script-src 'self'; script-src *"}, nil), "CSP_INVALID")
	})
	t.Run("fallback", func(t *testing.T) {
		findings := evaluateCSP("https://example.com/", []string{"default-src 'self' 'unsafe-eval' *"}, nil)
		assertFindingCode(t, findings, "CSP_UNSAFE_EVAL")
		assertFindingCode(t, findings, "CSP_WILDCARD_SCRIPT_SOURCE")
	})
	t.Run("script src overrides fallback", func(t *testing.T) {
		findings := evaluateCSP("https://example.com/", []string{"default-src * 'unsafe-eval'; script-src 'self'"}, nil)
		if len(findings) != 0 {
			t.Fatalf("unexpected findings: %+v", findings)
		}
	})
	t.Run("nonce neutralizes inline", func(t *testing.T) {
		findings := evaluateCSP("https://example.com/", []string{"script-src 'unsafe-inline' 'nonce-abc123'"}, nil)
		for _, item := range findings {
			if item.Code == "CSP_UNSAFE_INLINE_SCRIPT" {
				t.Fatalf("nonce produced false positive: %+v", findings)
			}
		}
	})
	t.Run("invalid nonce does not neutralize inline", func(t *testing.T) {
		findings := evaluateCSP("https://example.com/", []string{"script-src 'unsafe-inline' 'nonce-'"}, nil)
		assertFindingCode(t, findings, "CSP_UNSAFE_INLINE_SCRIPT")
	})
	t.Run("multiple policies restrict", func(t *testing.T) {
		findings := evaluateCSP("https://example.com/", []string{"script-src * 'unsafe-eval'", "script-src 'self'"}, nil)
		if len(findings) != 0 {
			t.Fatalf("combined policies should be restrictive: %+v", findings)
		}
	})
}

func TestStructuredHSTSObservations(t *testing.T) {
	header := make(http.Header)
	header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	observed := observeSecurityHeaders(header)
	if observed.HSTSMaxAge == nil || *observed.HSTSMaxAge != 31536000 || !observed.HSTSIncludeSubDomains || !observed.HSTSPreload {
		t.Fatalf("HSTS observations = %+v", observed)
	}
}

func TestFramingPrecedenceAndXFOValidation(t *testing.T) {
	if findings := evaluateFraming("https://example.com/", []string{"frame-ancestors 'none'"}, []string{"ALLOWALL"}); len(findings) != 0 {
		t.Fatalf("frame-ancestors should take precedence: %+v", findings)
	}
	assertFindingCode(t, evaluateFraming("https://example.com/", nil, nil), "CLICKJACKING_PROTECTION_MISSING")
	assertFindingCode(t, evaluateFraming("https://example.com/", nil, []string{"DENY", "SAMEORIGIN"}), "X_FRAME_OPTIONS_INVALID")
}

func TestReferrerAndPermissionsPolicies(t *testing.T) {
	assertFindingCode(t, evaluateReferrerPolicy("https://example.com/", nil), "REFERRER_POLICY_MISSING")
	assertFindingCode(t, evaluateReferrerPolicy("https://example.com/", []string{"origin, unsafe-url"}), "REFERRER_POLICY_UNSAFE_URL")
	if findings := evaluateReferrerPolicy("https://example.com/", []string{"unsafe-url, strict-origin"}); len(findings) != 0 {
		t.Fatalf("last valid policy should win: %+v", findings)
	}
	assertFindingCode(t, evaluatePermissionsPolicy("https://example.com/", nil), "PERMISSIONS_POLICY_MISSING")
	assertFindingCode(t, evaluatePermissionsPolicy("https://example.com/", []string{"camera=(*), geolocation=(), usb=*"}), "PERMISSIONS_POLICY_SENSITIVE_WILDCARD")
	observations := observeSensitivePermissions([]string{`camera=(*), microphone=(), geolocation=(self "https://maps.example")`})
	if len(observations) != 3 || observations[0].Feature != "camera" || observations[0].Allowlist[0] != "*" {
		t.Fatalf("permission observations = %+v", observations)
	}
}

func TestHTTPFindingOrderIsStable(t *testing.T) {
	page := HTTPPageResult{
		FinalURL: "https://example.com/", StatusCode: 200, ContentType: "text/html; charset=utf-8",
		SecurityHeaders: SecurityHeaders{
			StrictTransportSecurity: []string{"max-age=30"},
			ContentSecurityPolicy:   []string{"script-src * 'unsafe-eval' 'unsafe-inline'"},
			PermissionsPolicy:       []string{"camera=(*)"},
		},
	}
	first := evaluateHTTPPage(page, true)
	second := evaluateHTTPPage(page, true)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("finding order is not stable")
	}
}
