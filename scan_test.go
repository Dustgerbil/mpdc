package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// No test using this resolver can fall through to public DNS.
type fixtureResolver struct {
	ips      []net.IP
	cname    string
	ipErr    error
	lookupIP func(context.Context) ([]net.IP, error)
}

func (r fixtureResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r.cname != "" {
		return r.cname, nil
	}
	return host, nil
}
func (r fixtureResolver) LookupIP(ctx context.Context, _, _ string) ([]net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.lookupIP != nil {
		return r.lookupIP(ctx)
	}
	return r.ips, r.ipErr
}
func (r fixtureResolver) LookupHost(ctx context.Context, _ string) ([]string, error) {
	return []string{"192.0.2.53"}, ctx.Err()
}
func (r fixtureResolver) LookupMX(ctx context.Context, _ string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mail.example.com.", Pref: 10}}, ctx.Err()
}
func (r fixtureResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(host, "_dmarc."):
		return []string{"v=DMARC1; p=reject"}, nil
	case strings.HasPrefix(host, "_mta-sts."):
		return []string{"v=STSv1; id=1"}, nil
	case strings.HasPrefix(host, "_smtp._tls."):
		return []string{"v=TLSRPTv1; rua=mailto:tls@example.com"}, nil
	default:
		return []string{"v=spf1 -all", "unrelated"}, nil
	}
}
func fixtureHostScanner() *hostScanner {
	return &hostScanner{
		resolver: fixtureResolver{ips: []net.IP{net.ParseIP("192.0.2.1")}},
		query: func(ctx context.Context, _, _ string, _ uint16) (dnsWireResponse, error) {
			return dnsWireResponse{}, ctx.Err()
		},
		connect: func(ctx context.Context, _, _ string, _ *tls.Config) (tls.ConnectionState, bool, error) {
			if err := ctx.Err(); err != nil {
				return tls.ConnectionState{}, false, err
			}
			return tls.ConnectionState{}, false, errors.New("connection refused")
		},
		newHTTP: func(HTTPScanOptions) *httpScanner { panic("unexpected HTTP inspection") },
	}
}

func TestInspectHostOffline(t *testing.T) {
	scanner := fixtureHostScanner()
	scanner.resolver = fixtureResolver{cname: "canonical.example.com.", ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1")}}
	r := scanner.inspectHost(context.Background(), "example.com", options{concurrency: 2, dnsServer: "127.0.0.1:53", mail: true})
	if r.CNAME != "canonical.example.com" || len(r.Endpoints) != 2 || r.IPs[0] != "192.0.2.1" || r.Incomplete {
		t.Fatalf("result: %+v", r)
	}
	if r.HTTP != nil || r.Mail == nil || len(r.Mail.SPF) != 1 || len(r.Mail.DMARC) != 1 || len(r.Mail.MX) != 1 {
		t.Fatalf("optional inspection: %+v", r)
	}
	assertFindingCode(t, r.Findings, "HTTPS_UNREACHABLE")
	scanner.resolver = fixtureResolver{ipErr: &net.DNSError{IsNotFound: true}}
	r = scanner.inspectHost(context.Background(), "missing.example", options{dnsServer: "127.0.0.1:53"})
	assertFindingCode(t, r.Findings, "DNS_LOOKUP_FAILED")
	r = scanner.inspectHost(context.Background(), "", options{})
	assertFindingCode(t, r.Findings, "INPUT_INVALID")
}

func TestEndpointWorkerLimitAndCancellation(t *testing.T) {
	scanner := fixtureHostScanner()
	var active, peak, calls atomic.Int64
	started := make(chan struct{}, 64)
	scanner.connect = func(ctx context.Context, _, _ string, _ *tls.Config) (tls.ConnectionState, bool, error) {
		calls.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-ctx.Done()
		return tls.ConnectionState{}, false, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ips := make([]string, 30)
	for i := range ips {
		ips[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	done := make(chan []EndpointResult, 1)
	go func() { done <- scanner.inspectEndpoints(ctx, "example.com", ips, true, 3) }()
	for range 3 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	if peak.Load() != 3 {
		t.Fatalf("peak=%d", peak.Load())
	}
	cancel()
	select {
	case endpoints := <-done:
		if len(endpoints) != len(ips) {
			t.Fatal("lost endpoints")
		}
		for i, e := range endpoints {
			if e.IP != ips[i] || !e.Incomplete || len(e.Findings) != 0 {
				t.Errorf("endpoint %d: %+v", i, e)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("workers did not cancel")
	}
	if peak.Load() > 3 || active.Load() != 0 || calls.Load() != 3 {
		t.Fatalf("peak=%d active=%d calls=%d", peak.Load(), active.Load(), calls.Load())
	}
}

func TestScanBudgetSharedAcrossHosts(t *testing.T) {
	scanner := fixtureHostScanner()
	var calls atomic.Int64
	scanner.resolver = fixtureResolver{lookupIP: func(ctx context.Context) ([]net.IP, error) { calls.Add(1); <-ctx.Done(); return nil, ctx.Err() }}
	var output, stderr bytes.Buffer
	start := time.Now()
	code := run(context.Background(), []string{"-json", "-scan-timeout", "30ms", "first.example", "second.example"}, nil, &output, &stderr, scanner)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	if code != 1 || calls.Load() != 1 {
		t.Fatalf("code=%d calls=%d stderr=%s", code, calls.Load(), stderr.String())
	}
	if strings.Count(output.String(), `"incomplete": true`) != 2 || strings.Contains(output.String(), "DNS_LOOKUP_FAILED") {
		t.Fatalf("partial results: %s", output.String())
	}
}

func TestCanceledProbesRetainCompletedCertificate(t *testing.T) {
	scanner := fixtureHostScanner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cert := testCertificate(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	calls := 0
	scanner.connect = func(ctx context.Context, _, _ string, cfg *tls.Config) (tls.ConnectionState, bool, error) {
		calls++
		if calls == 1 {
			return tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}, true, nil
		}
		cancel()
		return tls.ConnectionState{}, false, ctx.Err()
	}
	endpoint := scanner.inspectEndpoint(ctx, "example.com", "192.0.2.1", true)
	if !endpoint.Incomplete || endpoint.Certificate == nil || !endpoint.CertificateValid || calls != 2 {
		t.Fatalf("partial endpoint: %+v calls=%d", endpoint, calls)
	}
	for _, f := range endpoint.Findings {
		if f.Code == "HTTPS_UNREACHABLE" || f.Code == "TLS_HANDSHAKE_FAILED" {
			t.Fatalf("false finding: %+v", f)
		}
	}
}

func TestInspectHostHTTPOptIn(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/.well-known/security.txt" {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "Contact: mailto:security@example.com\nExpires: 2031-01-01T00:00:00Z\n")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "session=private-value; HttpOnly")
		io.WriteString(w, "private-body")
	}))
	defer server.Close()
	clear := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://example.com/", 301) }))
	defer clear.Close()
	scanner := fixtureHostScanner()
	scanner.newHTTP = func(opts HTTPScanOptions) *httpScanner {
		return testScanner(opts, &routeDialer{httpAddress: clear.Listener.Addr().String(), httpsAddress: server.Listener.Addr().String()})
	}
	opts := options{dnsServer: "127.0.0.1:53"}
	r := scanner.inspectHost(context.Background(), "example.com", opts)
	if r.HTTP != nil || requests.Load() != 0 {
		t.Fatal("HTTP was not opt-in")
	}
	opts.http = defaultHTTPOptions()
	r = scanner.inspectHost(context.Background(), "example.com", opts)
	if r.HTTP == nil || !r.HTTP.SecurityTXT.Present || len(r.HTTP.Pages) != 1 || requests.Load() != 3 {
		t.Fatalf("HTTP inspection: %+v requests=%d", r.HTTP, requests.Load())
	}
	assertFindingCode(t, r.Findings, "COOKIE_SECURE_MISSING")
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "private-value") || strings.Contains(string(encoded), "private-body") {
		t.Fatal("HTTP secret leaked into result")
	}
}
