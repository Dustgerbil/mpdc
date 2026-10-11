package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type staticResolver struct {
	addresses map[string][]net.IPAddr
	err       error
}

func (resolver staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if resolver.err != nil {
		return nil, resolver.err
	}
	if values, ok := resolver.addresses[host]; ok {
		return values, nil
	}
	return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
}

type routeDialer struct {
	httpAddress  string
	httpsAddress string
	calls        atomic.Int64
}

func (dialer *routeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer.calls.Add(1)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	target := dialer.httpAddress
	if port == "443" {
		target = dialer.httpsAddress
	}
	if target == "" {
		return nil, errors.New("no test route")
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func testScanner(options HTTPScanOptions, dialer httpDialer) *httpScanner {
	return &httpScanner{
		options: options,
		resolver: staticResolver{addresses: map[string][]net.IPAddr{
			"example.com":       {{IP: net.ParseIP("8.8.8.8")}},
			"allowed.example":   {{IP: net.ParseIP("1.1.1.1")}},
			"elsewhere.example": {{IP: net.ParseIP("9.9.9.9")}},
		}},
		dialer:    dialer,
		tlsConfig: &tls.Config{InsecureSkipVerify: true}, // Test-only routing to httptest certificates.
		now:       func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
}

func defaultHTTPOptions() HTTPScanOptions {
	return HTTPScanOptions{Enabled: true, Paths: []string{"/"}, Timeout: time.Second, MaxRedirects: 10, MaxBodyBytes: 1 << 20}
}

func TestHTTPRedirectToHTTPSAndNoCookieReplay(t *testing.T) {
	var secureRequests atomic.Int64
	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		secureRequests.Add(1)
		if request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Origin") != "" || request.Referer() != "" {
			t.Errorf("unexpected state-bearing request headers: %#v", request.Header)
		}
		if got := request.Header.Get("User-Agent"); got != "mpdc/0.2.0" {
			t.Errorf("User-Agent = %q", got)
		}
		response.Header().Set("Content-Type", "text/html")
		response.Header().Set("Strict-Transport-Security", "max-age=31536000")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("Permissions-Policy", "camera=(), microphone=()")
		response.Header().Add("Set-Cookie", "session=secret-value; Secure; HttpOnly; SameSite=Lax; Path=/")
		_, _ = response.Write([]byte("private body text"))
	}))
	defer httpsServer.Close()
	httpServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Add("Set-Cookie", "cleartext=must-not-replay")
		http.Redirect(response, request, "https://example.com/", http.StatusMovedPermanently)
	}))
	defer httpServer.Close()

	dialer := &routeDialer{httpAddress: httpServer.Listener.Addr().String(), httpsAddress: httpsServer.Listener.Addr().String()}
	scanner := testScanner(defaultHTTPOptions(), dialer)
	page, _ := scanner.fetchPage(context.Background(), "http://example.com/", "example.com", map[string]bool{"example.com": true}, 1024, false)
	if page.FinalURL != "https://example.com/" || len(page.RedirectChain) != 1 || !page.RedirectChain[0].Followed {
		t.Fatalf("unexpected redirect result: %+v", page)
	}
	if secureRequests.Load() != 1 {
		t.Fatalf("secure requests = %d", secureRequests.Load())
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-value", "must-not-replay", "private body text"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("JSON retained secret %q: %s", secret, encoded)
		}
	}
}

func TestCleartextWithoutRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	dialer := &routeDialer{httpAddress: server.Listener.Addr().String()}
	scanner := testScanner(defaultHTTPOptions(), dialer)
	page, _ := scanner.fetchPage(context.Background(), "http://example.com/", "example.com", map[string]bool{"example.com": true}, 1024, false)
	findings := evaluateCleartextRedirect(page)
	assertFindingCode(t, findings, "HTTP_NO_HTTPS_REDIRECT")
}

func TestRedirectStops(t *testing.T) {
	tests := []struct {
		name       string
		location   string
		code       string
		stopReason string
	}{
		{name: "downgrade", location: "http://example.com/next", code: "HTTP_REDIRECT_TO_INSECURE", stopReason: "insecure_downgrade"},
		{name: "out of scope", location: "https://elsewhere.example/", code: "HTTP_REDIRECT_OUT_OF_SCOPE", stopReason: "out_of_scope"},
		{name: "unsupported", location: "ftp://example.com/file", code: "HTTP_REDIRECT_UNSUPPORTED_SCHEME", stopReason: "unsupported_scheme"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Location", test.location)
				response.WriteHeader(http.StatusFound)
			}))
			defer server.Close()
			dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
			scanner := testScanner(defaultHTTPOptions(), dialer)
			page, _ := scanner.fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{"example.com": true}, 1024, false)
			assertFindingCode(t, page.Findings, test.code)
			if got := page.RedirectChain[0].StopReason; got != test.stopReason || page.RedirectChain[0].Followed {
				t.Fatalf("redirect hop = %+v", page.RedirectChain[0])
			}
		})
	}
}

func TestAllowedRedirectHostIsFollowed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host == "example.com" {
			http.Redirect(response, request, "https://allowed.example/final", http.StatusFound)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
	scanner := testScanner(defaultHTTPOptions(), dialer)
	page, _ := scanner.fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{
		"example.com": true, "allowed.example": true,
	}, 1024, false)
	if page.FinalURL != "https://allowed.example/final" || page.StatusCode != http.StatusNoContent || !page.RedirectChain[0].Followed {
		t.Fatalf("allowed redirect result = %+v", page)
	}
}

func TestPrivateRedirectTargetIsBlockedBeforeDial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, "https://allowed.example/private", http.StatusFound)
	}))
	defer server.Close()
	dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
	scanner := testScanner(defaultHTTPOptions(), dialer)
	scanner.resolver = staticResolver{addresses: map[string][]net.IPAddr{
		"example.com":     {{IP: net.ParseIP("8.8.8.8")}},
		"allowed.example": {{IP: net.ParseIP("10.0.0.1")}},
	}}
	page, _ := scanner.fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{
		"example.com": true, "allowed.example": true,
	}, 1024, false)
	assertFindingCode(t, page.Findings, "HTTP_TARGET_ADDRESS_BLOCKED")
	if dialer.calls.Load() != 1 {
		t.Fatalf("expected only the initial connection, got %d dials", dialer.calls.Load())
	}
}

func TestRedirectLoopAndLimit(t *testing.T) {
	loopServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/a" {
			http.Redirect(response, request, "/b", http.StatusFound)
			return
		}
		http.Redirect(response, request, "/a", http.StatusFound)
	}))
	defer loopServer.Close()
	dialer := &routeDialer{httpsAddress: loopServer.Listener.Addr().String()}
	scanner := testScanner(defaultHTTPOptions(), dialer)
	page, _ := scanner.fetchPage(context.Background(), "https://example.com/a", "example.com", map[string]bool{"example.com": true}, 1024, false)
	assertFindingCode(t, page.Findings, "HTTP_REDIRECT_LOOP")

	options := defaultHTTPOptions()
	options.MaxRedirects = 1
	limitServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/a" {
			http.Redirect(response, request, "/b", http.StatusFound)
			return
		}
		http.Redirect(response, request, "/c", http.StatusFound)
	}))
	defer limitServer.Close()
	limitDialer := &routeDialer{httpsAddress: limitServer.Listener.Addr().String()}
	scanner = testScanner(options, limitDialer)
	page, _ = scanner.fetchPage(context.Background(), "https://example.com/a", "example.com", map[string]bool{"example.com": true}, 1024, false)
	assertFindingCode(t, page.Findings, "HTTP_REDIRECT_LIMIT_REACHED")
}

func TestBlockedAddressNeverDialed(t *testing.T) {
	dialer := &routeDialer{}
	scanner := testScanner(defaultHTTPOptions(), dialer)
	scanner.resolver = staticResolver{addresses: map[string][]net.IPAddr{
		"example.com": {{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("8.8.8.8")}},
	}}
	page, _ := scanner.fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{"example.com": true}, 1024, false)
	assertFindingCode(t, page.Findings, "HTTP_TARGET_ADDRESS_BLOCKED")
	if dialer.calls.Load() != 0 {
		t.Fatalf("dialer was called %d times", dialer.calls.Load())
	}
}

func TestSpecialPurposeHTTPAddressPolicy(t *testing.T) {
	tests := []struct {
		address string
		blocked bool
	}{
		{"0.1.2.3", true},
		{"192.0.0.8", true},
		{"192.0.0.9", false},
		{"192.88.99.2", true},
		{"8.8.8.8", false},
		{"64:ff9b::808:808", true},
		{"100::1", true},
		{"2001::1", true},
		{"2001:1::1", false},
		{"2001:db8::1", true},
		{"2002::1", true},
		{"2606:4700:4700::1111", false},
		{"4000::1", true},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := blockedHTTPAddress(net.ParseIP(test.address)); got != test.blocked {
				t.Fatalf("blockedHTTPAddress(%s) = %t, want %t", test.address, got, test.blocked)
			}
		})
	}
}

func TestEgressHTTPDialerEnforcesLiteralPublicAddressAndPort(t *testing.T) {
	next := &routeDialer{}
	dialer := egressHTTPDialer{next: next}
	for _, test := range []struct {
		network string
		address string
	}{
		{"tcp", "127.0.0.1:443"},
		{"tcp", "example.com:443"},
		{"tcp", "8.8.8.8:8443"},
		{"udp", "8.8.8.8:443"},
	} {
		if _, err := dialer.DialContext(context.Background(), test.network, test.address); !errors.Is(err, errHTTPAddressBlocked) {
			t.Errorf("DialContext(%q, %q) error = %v", test.network, test.address, err)
		}
	}
	if next.calls.Load() != 0 {
		t.Fatalf("blocked egress reached underlying dialer %d times", next.calls.Load())
	}
	_, err := dialer.DialContext(context.Background(), "tcp", "8.8.8.8:443")
	if errors.Is(err, errHTTPAddressBlocked) || next.calls.Load() != 1 {
		t.Fatalf("public egress did not reach underlying dialer: calls=%d err=%v", next.calls.Load(), err)
	}
}

func TestBodyHeaderLimitsAndTimeout(t *testing.T) {
	t.Run("body", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(strings.Repeat("x", 100)))
		}))
		defer server.Close()
		dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
		page, body := testScanner(defaultHTTPOptions(), dialer).fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{"example.com": true}, 16, false)
		if !page.BodyTruncated || page.BytesRead != 16 || len(body) != 16 {
			t.Fatalf("body limit result = %+v, len=%d", page, len(body))
		}
	})

	t.Run("header", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("X-Oversized", strings.Repeat("x", maxHTTPResponseHeaders+1))
			response.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
		page, _ := testScanner(defaultHTTPOptions(), dialer).fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{"example.com": true}, 16, false)
		if page.Error == "" {
			t.Fatal("expected oversized header error")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			response.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
		options := defaultHTTPOptions()
		options.Timeout = 10 * time.Millisecond
		page, _ := testScanner(options, dialer).fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{"example.com": true}, 16, false)
		if page.Error == "" || !(strings.Contains(page.Error, "timeout") || strings.Contains(page.Error, "deadline exceeded")) {
			t.Fatalf("timeout error = %q", page.Error)
		}
	})
}

func TestHTTPPathValidation(t *testing.T) {
	valid := []string{"/", "/login", "/a%20b?mode=test"}
	for _, value := range valid {
		if err := validateHTTPPath(value); err != nil {
			t.Errorf("validateHTTPPath(%q) = %v", value, err)
		}
	}
	invalid := []string{"", "relative", "//evil.example/", "https://evil.example/", "/path#fragment", "/bad%zz", "/line\nbreak", "/encoded%0abreak"}
	for _, value := range invalid {
		if err := validateHTTPPath(value); err == nil {
			t.Errorf("validateHTTPPath(%q) succeeded", value)
		}
	}
}

func TestRedirectUserinfoIsRejectedAndRedacted(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://user:secret@example.com/private")
		response.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
	page, _ := testScanner(defaultHTTPOptions(), dialer).fetchPage(context.Background(),
		"https://example.com/", "example.com", map[string]bool{"example.com": true}, 16, false)
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if page.Error == "" || strings.Contains(string(encoded), "secret") {
		t.Fatalf("userinfo was not safely rejected: %s", encoded)
	}
}

func TestRedirectQueryValuesAreRedactedEverywhere(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			response.Header().Set("Location", "/next?state=state-secret&nonce=nonce-secret&flag")
			response.WriteHeader(http.StatusFound)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
	page, _ := testScanner(defaultHTTPOptions(), dialer).fetchPage(context.Background(),
		"https://example.com/start?initial=initial-secret", "example.com", map[string]bool{"example.com": true}, 16, false)
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, secret := range []string{"state-secret", "nonce-secret", "initial-secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("JSON retained query value %q: %s", secret, output)
		}
	}
	for _, parameter := range []string{"initial=[redacted]", "state=[redacted]", "nonce=[redacted]", "flag"} {
		if !strings.Contains(output, parameter) {
			t.Fatalf("JSON did not preserve redacted parameter %q: %s", parameter, output)
		}
	}
	if strings.Contains(page.Error, "secret") {
		t.Fatalf("error retained query value: %q", page.Error)
	}

	failedPage, _ := testScanner(defaultHTTPOptions(), &routeDialer{}).fetchPage(context.Background(),
		"https://example.com/fail?error_token=error-secret", "example.com", map[string]bool{"example.com": true}, 16, false)
	failedJSON, err := json.Marshal(failedPage)
	if err != nil {
		t.Fatal(err)
	}
	if failedPage.Error == "" || strings.Contains(string(failedJSON), "error-secret") || !strings.Contains(string(failedJSON), "error_token=[redacted]") {
		t.Fatalf("error output was not query-redacted: %s", failedJSON)
	}
}

func TestURLRedactionHandlesMalformedValues(t *testing.T) {
	redacted := redactURLForOutput("https://user:password@example.com/path?state=secret&flag#fragment")
	if strings.Contains(redacted, "password") || strings.Contains(redacted, "secret") || !strings.Contains(redacted, "state=[redacted]") {
		t.Fatalf("redacted URL = %q", redacted)
	}
	malformed := redactURLForOutput("https://example.com/%zz?token=secret&flag")
	if strings.Contains(malformed, "secret") || !strings.Contains(malformed, "token=[redacted]") {
		t.Fatalf("malformed redacted URL = %q", malformed)
	}
}

func TestJSONSchemaTwoAndHTTPOmission(t *testing.T) {
	without, err := json.Marshal(Result{SchemaVersion: jsonSchemaVersion, Hostname: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(without), `"schema_version":2`) || strings.Contains(string(without), `"http"`) {
		t.Fatalf("unexpected JSON without HTTP: %s", without)
	}
	with, err := json.Marshal(Result{SchemaVersion: jsonSchemaVersion, Hostname: "example.com", HTTP: &HTTPInspection{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(with), `"http"`) {
		t.Fatalf("HTTP object missing: %s", with)
	}
}

func TestFailedInspectionDoesNotPoisonNext(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dialer := &routeDialer{httpAddress: server.Listener.Addr().String(), httpsAddress: server.Listener.Addr().String()}
	scanner := testScanner(defaultHTTPOptions(), dialer)
	failed := scanner.inspect(context.Background(), "https://bad.example")
	if len(failed.Errors) == 0 {
		t.Fatal("expected invalid hostname error")
	}
	page, _ := scanner.fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{"example.com": true}, 16, false)
	if page.StatusCode != http.StatusNoContent {
		t.Fatalf("subsequent status = %d, error = %s", page.StatusCode, page.Error)
	}
}

func TestStableFindingOrder(t *testing.T) {
	page := HTTPPageResult{
		FinalURL: "https://example.com/", StatusCode: 200, ContentType: "text/html",
		SecurityHeaders: SecurityHeaders{},
	}
	first := evaluateHTTPPage(page, true)
	second := evaluateHTTPPage(page, true)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("finding order changed:\n%+v\n%+v", first, second)
	}
}

func assertFindingCode(t *testing.T, findings []Finding, code string) {
	t.Helper()
	for _, item := range findings {
		if item.Code == code {
			return
		}
	}
	t.Fatalf("finding %s missing from %+v", code, findings)
}

func TestRedirectCookieEvidence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			t.Error("cookie replayed")
		}
		if r.URL.Path == "/" {
			w.Header().Set("Set-Cookie", "session=redirect-secret; HttpOnly")
			http.Redirect(w, r, "/final?token=query-secret", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "final=final-secret; Secure; HttpOnly; SameSite=Strict")
		w.Write([]byte("body-secret"))
	}))
	defer server.Close()
	scanner := testScanner(defaultHTTPOptions(), &routeDialer{httpsAddress: server.Listener.Addr().String()})
	page, _ := scanner.fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{"example.com": true}, 1024, true)
	assertFindingCode(t, page.Findings, "COOKIE_SECURE_MISSING")
	if len(page.RedirectChain) != 1 || len(page.RedirectChain[0].Cookies) != 1 || page.RedirectChain[0].Cookies[0].Name != "session" {
		t.Fatalf("hop evidence: %+v", page.RedirectChain)
	}
	if len(page.Cookies) != 1 || page.Cookies[0].Name != "final" {
		t.Fatalf("final cookies changed meaning: %+v", page.Cookies)
	}
	encoded, _ := json.Marshal(page)
	for _, secret := range []string{"redirect-secret", "final-secret", "query-secret", "body-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("leaked %s", secret)
		}
	}
}

func TestStoppedRedirectCookieEvidence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=secret")
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	defer server.Close()
	scanner := testScanner(defaultHTTPOptions(), &routeDialer{httpsAddress: server.Listener.Addr().String()})
	page, _ := scanner.fetchPage(context.Background(), "https://example.com/", "example.com", map[string]bool{"example.com": true}, 1024, true)
	assertFindingCode(t, page.Findings, "COOKIE_SECURE_MISSING")
	if len(page.RedirectChain) != 1 || page.RedirectChain[0].Followed || len(page.RedirectChain[0].Cookies) != 1 {
		t.Fatalf("%+v", page)
	}
}

func TestHTTPScanBudgetAcrossRedirects(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/slow", 302)
			return
		}
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	scanner := testScanner(defaultHTTPOptions(), &routeDialer{httpsAddress: server.Listener.Addr().String()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan HTTPPageResult, 1)
	go func() {
		p, _ := scanner.fetchPage(ctx, "https://example.com/", "example.com", map[string]bool{"example.com": true}, 1024, true)
		done <- p
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("second request not started")
	}
	cancel()
	select {
	case p := <-done:
		if !strings.Contains(p.Error, "context canceled") || len(p.RedirectChain) != 1 {
			t.Fatalf("%+v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not stop HTTP")
	}
	scanner.inspect(ctx, "example.com")
	if calls.Load() != 2 {
		t.Fatalf("new requests after cancellation: %d", calls.Load())
	}
}
