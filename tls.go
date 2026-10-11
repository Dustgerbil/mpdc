package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func (scanner *hostScanner) inspectEndpoints(ctx context.Context, host string, ips []string, scanCiphers bool, concurrency int) []EndpointResult {
	results := make([]EndpointResult, len(ips))
	var wg sync.WaitGroup
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	concurrency = min(concurrency, maxConcurrency, len(ips))
	jobs := make(chan int)
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index] = scanner.inspectEndpoint(ctx, host, ips[index], scanCiphers)
			}
		}()
	}
	for index, ip := range ips {
		if ctx.Err() != nil {
			results[index] = incompleteEndpoint(ip, ctx.Err())
			continue
		}
		select {
		case jobs <- index:
		case <-ctx.Done():
			results[index] = incompleteEndpoint(ip, ctx.Err())
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func (scanner *hostScanner) inspectEndpoint(ctx context.Context, host, ip string, scanCiphers bool) (endpoint EndpointResult) {
	if ctx.Err() != nil {
		return incompleteEndpoint(ip, ctx.Err())
	}
	endpoint = EndpointResult{
		IP:               ip,
		AddressFamily:    addressFamily(ip),
		IPClassification: classifyIP(ip),
	}

	defer func() {
		if ctx.Err() != nil {
			endpoint.Incomplete = true
			endpoint.Error = joinErrors(endpoint.Error, "endpoint inspection incomplete: "+ctx.Err().Error())
		}
		addEndpointFindings(&endpoint)
	}()
	verifiedState, tcpReachable, err := scanner.connect(ctx, host, ip, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
	})
	endpoint.TCPReachable = tcpReachable
	if err == nil {
		endpoint.TLSHandshake = true
		endpoint.CertificateValid = true
		endpoint.ChainTrusted = true
		endpoint.HostnameMatch = true
		populateTLSState(&endpoint, verifiedState, true)
	} else {
		if tcpReachable {
			endpoint.VerificationError = classifyTLSError(err)
		}

		if ctx.Err() != nil {
			return endpoint
		}
		diagnosticState, diagnosticTCP, diagnosticErr := scanner.connect(ctx, host, ip, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // Diagnostic retry only; the result remains explicitly untrusted.
			NextProtos:         []string{"h2", "http/1.1"},
		})
		endpoint.TCPReachable = endpoint.TCPReachable || diagnosticTCP
		if diagnosticErr != nil {
			endpoint.Error = fmt.Sprintf("TLS connection failed: %v", err)
			if diagnosticErr.Error() != err.Error() {
				endpoint.Error += fmt.Sprintf("; diagnostic retry failed: %v", diagnosticErr)
			}
		} else {
			endpoint.TLSHandshake = true
			populateTLSState(&endpoint, diagnosticState, false)
			evaluateDiagnosticCertificate(&endpoint, host, diagnosticState.PeerCertificates)
		}
	}

	endpoint.SupportedTLSVersions = scanner.scanTLSVersions(ctx, host, ip)
	if scanCiphers {
		endpoint.SupportedCipherSuites = scanner.scanCipherSuites(ctx, host, ip)
	}
	return endpoint
}

func connectTLS(ctx context.Context, host, ip string, config *tls.Config) (tls.ConnectionState, bool, error) {
	return connectTLSWithDialer(ctx, host, ip, config, &net.Dialer{Timeout: connectionTimeout})
}

func connectTLSWithDialer(ctx context.Context, host, ip string, config *tls.Config, dialer httpDialer) (tls.ConnectionState, bool, error) {
	var empty tls.ConnectionState
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return empty, false, err
	}

	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return empty, true, err
	}

	conn := tls.Client(raw, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return empty, true, err
	}
	state := conn.ConnectionState()
	conn.Close()
	return state, true, nil
}

func populateTLSState(endpoint *EndpointResult, state tls.ConnectionState, verified bool) {
	endpoint.TLSVersion = tlsVersionToString(state.Version)
	endpoint.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	if state.CurveID != 0 {
		endpoint.KeyExchange = state.CurveID.String()
	}
	endpoint.ALPN = state.NegotiatedProtocol
	endpoint.ServerName = state.ServerName
	endpoint.OCSPStapled = len(state.OCSPResponse) > 0
	endpoint.OCSPResponseBytes = len(state.OCSPResponse)
	endpoint.SCTCount = len(state.SignedCertificateTimestamps)

	now := time.Now()
	for _, cert := range state.PeerCertificates {
		endpoint.PeerChain = append(endpoint.PeerChain, certificateInfo(cert, now))
	}
	endpoint.peerCertificates = append([]*x509.Certificate(nil), state.PeerCertificates...)
	if len(state.PeerCertificates) > 0 {
		info := certificateInfo(state.PeerCertificates[0], now)
		endpoint.Certificate = &info
	}
	if verified && len(state.VerifiedChains) > 0 {
		endpoint.verifiedCertificates = append([]*x509.Certificate(nil), state.VerifiedChains[0]...)
		for _, cert := range state.VerifiedChains[0] {
			endpoint.VerifiedChain = append(endpoint.VerifiedChain, certificateInfo(cert, now))
		}
	}
}

func evaluateDiagnosticCertificate(endpoint *EndpointResult, host string, peerCertificates []*x509.Certificate) {
	if len(peerCertificates) == 0 {
		return
	}
	leaf := peerCertificates[0]
	endpoint.HostnameMatch = leaf.VerifyHostname(host) == nil

	intermediates := x509.NewCertPool()
	for _, cert := range peerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	now := time.Now()
	verificationTime := now
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		verificationTime = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   verificationTime,
	})
	endpoint.ChainTrusted = err == nil
	endpoint.CertificateValid = endpoint.HostnameMatch && endpoint.ChainTrusted &&
		!now.Before(leaf.NotBefore) && !now.After(leaf.NotAfter)
}

func (scanner *hostScanner) scanTLSVersions(ctx context.Context, host, ip string) []string {
	versions := []struct {
		id   uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}
	cipherSuites := allTLS12CipherSuiteIDs()
	var supported []string
	for _, version := range versions {
		if ctx.Err() != nil {
			break
		}
		config := &tls.Config{
			ServerName:             host,
			InsecureSkipVerify:     true,
			MinVersion:             version.id,
			MaxVersion:             version.id,
			SessionTicketsDisabled: true,
		}
		if version.id <= tls.VersionTLS12 {
			config.CipherSuites = cipherSuites
		}
		if _, _, err := scanner.connect(ctx, host, ip, config); err == nil {
			supported = append(supported, version.name)
		}
	}
	return supported
}

func (scanner *hostScanner) scanCipherSuites(ctx context.Context, host, ip string) map[string][]string {
	accepted := make(map[string][]string)
	versions := []struct {
		id   uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
	}
	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	for _, version := range versions {
		if ctx.Err() != nil {
			break
		}
		for _, suite := range suites {
			if ctx.Err() != nil {
				break
			}
			if !containsUint16(suite.SupportedVersions, version.id) {
				continue
			}
			config := &tls.Config{
				ServerName:             host,
				InsecureSkipVerify:     true,
				MinVersion:             version.id,
				MaxVersion:             version.id,
				CipherSuites:           []uint16{suite.ID},
				SessionTicketsDisabled: true,
			}
			if _, _, err := scanner.connect(ctx, host, ip, config); err == nil {
				accepted[version.name] = append(accepted[version.name], suite.Name)
			}
		}
	}
	if len(accepted) == 0 {
		return nil
	}
	return accepted
}

func allTLS12CipherSuiteIDs() []uint16 {
	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	ids := make([]uint16, 0, len(suites))
	seen := make(map[uint16]bool)
	for _, suite := range suites {
		if seen[suite.ID] || !containsAnyTLS12Version(suite.SupportedVersions) {
			continue
		}
		seen[suite.ID] = true
		ids = append(ids, suite.ID)
	}
	return ids
}

func containsAnyTLS12Version(versions []uint16) bool {
	for _, version := range versions {
		if version >= tls.VersionTLS10 && version <= tls.VersionTLS12 {
			return true
		}
	}
	return false
}

func containsUint16(values []uint16, wanted uint16) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}

func classifyTLSError(err error) string {
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return fmt.Sprintf("hostname mismatch: %v", hostnameError)
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return fmt.Sprintf("unknown certificate authority: %v", unknownAuthority)
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return fmt.Sprintf("invalid certificate: %v", invalid)
	}
	var systemRoots x509.SystemRootsError
	if errors.As(err, &systemRoots) {
		return fmt.Sprintf("system trust store error: %v", systemRoots)
	}
	return err.Error()
}

func isLocalNetworkUnavailable(message string) bool {
	message = strings.ToLower(message)
	return strings.Contains(message, "no route to host") ||
		strings.Contains(message, "network is unreachable") ||
		strings.Contains(message, "network unreachable")
}

func incompleteEndpoint(ip string, err error) EndpointResult {
	return EndpointResult{IP: ip, AddressFamily: addressFamily(ip), IPClassification: classifyIP(ip), Incomplete: true, Error: "endpoint inspection incomplete: " + err.Error()}
}
