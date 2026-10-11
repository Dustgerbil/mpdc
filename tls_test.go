package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testCertificate(t *testing.T, host string, from, to time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	feature, _ := asn1.Marshal([]int{5})
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host, "*.example.com"}, NotBefore: from, NotAfter: to, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}, Value: feature}}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCertificateDiagnosticsAndFindings(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name         string
		from, to     time.Time
		status, code string
	}{
		{"expired", now.Add(-48 * time.Hour), now.Add(-time.Hour), "expired", "CERT_EXPIRED"},
		{"future", now.Add(time.Hour), now.Add(90 * 24 * time.Hour), "not_yet_valid", "CERT_NOT_YET_VALID"},
		{"valid", now.Add(-time.Hour), now.Add(90 * 24 * time.Hour), "valid", "CERT_MUST_STAPLE_MISSING"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := testCertificate(t, "example.com", tc.from, tc.to)
			info := certificateInfo(cert, now)
			if info.TimeStatus != tc.status || info.PublicKeyBits != 256 || !info.MustStaple || len(info.WildcardAltNames) != 1 || len(info.FingerprintSHA256) != 95 {
				t.Fatalf("metadata: %+v", info)
			}
			e := EndpointResult{IP: "192.0.2.1", TCPReachable: true, TLSHandshake: true, Certificate: &info}
			evaluateDiagnosticCertificate(&e, "example.com", []*x509.Certificate{cert})
			if !e.HostnameMatch || e.ChainTrusted || e.CertificateValid {
				t.Fatalf("self-signed trust: %+v", e)
			}
			addEndpointFindings(&e)
			assertFindingCode(t, e.Findings, tc.code)
			assertFindingCode(t, e.Findings, "CERT_UNTRUSTED")
			evaluateDiagnosticCertificate(&e, "unrelated.test", []*x509.Certificate{cert})
			if e.HostnameMatch {
				t.Fatal("hostname mismatch missed")
			}
		})
	}
}

func TestTLSVerifiedAndDiagnosticHandshake(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dialer := &routeDialer{httpsAddress: server.Listener.Addr().String()}
	cfg := &tls.Config{ServerName: "example.com", RootCAs: roots}
	state, reachable, err := connectTLSWithDialer(context.Background(), "example.com", "192.0.2.1", cfg, dialer)
	if err != nil || !reachable || len(state.VerifiedChains) == 0 {
		t.Fatalf("verified handshake: %v %v", reachable, err)
	}
	// A mismatch is rejected; only the explicitly diagnostic connection bypasses it.
	cfg = cfg.Clone()
	cfg.ServerName = "wrong.test"
	_, reachable, err = connectTLSWithDialer(context.Background(), "wrong.test", "192.0.2.1", cfg, dialer)
	var mismatch x509.HostnameError
	if !reachable || !errors.As(err, &mismatch) {
		t.Fatalf("expected hostname error: %v", err)
	}
	cfg.InsecureSkipVerify = true
	state, _, err = connectTLSWithDialer(context.Background(), "wrong.test", "192.0.2.1", cfg, dialer)
	if err != nil || len(state.VerifiedChains) != 0 {
		t.Fatalf("diagnostic handshake: %v", err)
	}
	// Probe the real loopback TLS server through the same connector used in production.
	scanner := fixtureHostScanner()
	scanner.connect = func(ctx context.Context, host, ip string, cfg *tls.Config) (tls.ConnectionState, bool, error) {
		cfg = cfg.Clone()
		cfg.RootCAs = roots
		return connectTLSWithDialer(ctx, host, ip, cfg, dialer)
	}
	e := scanner.inspectEndpoint(context.Background(), "example.com", "192.0.2.1", false)
	if !e.CertificateValid || len(e.SupportedTLSVersions) != 1 || e.SupportedTLSVersions[0] != "TLS 1.2" {
		t.Fatalf("probes: %+v", e)
	}
}

func TestTLSHandshakeCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := connectTLSWithDialer(ctx, "example.com", "192.0.2.1", &tls.Config{ServerName: "example.com"}, &routeDialer{httpsAddress: listener.Addr().String()})
		done <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("not accepted")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake ignored cancellation")
	}
}

func TestCipherProbeConfiguration(t *testing.T) {
	scanner := fixtureHostScanner()
	calls := 0
	scanner.connect = func(_ context.Context, _, _ string, cfg *tls.Config) (tls.ConnectionState, bool, error) {
		calls++
		if !cfg.InsecureSkipVerify || cfg.MinVersion != cfg.MaxVersion || len(cfg.CipherSuites) != 1 || cfg.MaxVersion > tls.VersionTLS12 {
			t.Errorf("unexpected config: %+v", cfg)
		}
		if cfg.MinVersion == tls.VersionTLS12 && cfg.CipherSuites[0] == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			return tls.ConnectionState{}, true, nil
		}
		return tls.ConnectionState{}, true, errors.New("unsupported")
	}
	supported := scanner.scanCipherSuites(context.Background(), "example.com", "192.0.2.1")
	if calls == 0 || len(supported) != 1 || len(supported["TLS 1.2"]) != 1 {
		t.Fatalf("supported=%v calls=%d", supported, calls)
	}
}
