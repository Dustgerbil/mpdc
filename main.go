package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	connectionTimeout = 5 * time.Second
	jsonSchemaVersion = 2
)

var version = "0.2.0"

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type CertificateInfo struct {
	Subject                string    `json:"subject"`
	Issuer                 string    `json:"issuer"`
	AltNames               []string  `json:"alt_names,omitempty"`
	WildcardAltNames       []string  `json:"wildcard_alt_names,omitempty"`
	Issued                 time.Time `json:"issued"`
	Expiry                 time.Time `json:"expiry"`
	DaysRemaining          int       `json:"days_remaining"`
	TimeStatus             string    `json:"time_status"`
	SerialNumber           string    `json:"serial_number"`
	FingerprintSHA256      string    `json:"fingerprint_sha256"`
	PublicKeyAlgorithm     string    `json:"public_key_algorithm"`
	PublicKeyBits          int       `json:"public_key_bits,omitempty"`
	PublicKeyCurve         string    `json:"public_key_curve,omitempty"`
	SignatureAlgorithm     string    `json:"signature_algorithm"`
	KeyUsage               []string  `json:"key_usage,omitempty"`
	ExtendedKeyUsage       []string  `json:"extended_key_usage,omitempty"`
	IsCA                   bool      `json:"is_ca"`
	OCSPServers            []string  `json:"ocsp_servers,omitempty"`
	CRLDistributionPoints  []string  `json:"crl_distribution_points,omitempty"`
	IssuingCertificateURLs []string  `json:"issuing_certificate_urls,omitempty"`
	TLSFeatures            []int     `json:"tls_features,omitempty"`
	MustStaple             bool      `json:"must_staple"`
}

type EndpointResult struct {
	IP                    string              `json:"ip"`
	AddressFamily         string              `json:"address_family"`
	IPClassification      string              `json:"ip_classification"`
	TCPReachable          bool                `json:"tcp_reachable"`
	TLSHandshake          bool                `json:"tls_handshake"`
	CertificateValid      bool                `json:"certificate_valid"`
	ChainTrusted          bool                `json:"chain_trusted"`
	HostnameMatch         bool                `json:"hostname_match"`
	TLSVersion            string              `json:"tls_version,omitempty"`
	CipherSuite           string              `json:"cipher_suite,omitempty"`
	KeyExchange           string              `json:"key_exchange,omitempty"`
	ALPN                  string              `json:"alpn,omitempty"`
	ServerName            string              `json:"server_name,omitempty"`
	SupportedTLSVersions  []string            `json:"supported_tls_versions,omitempty"`
	SupportedCipherSuites map[string][]string `json:"supported_cipher_suites,omitempty"`
	Certificate           *CertificateInfo    `json:"certificate,omitempty"`
	PeerChain             []CertificateInfo   `json:"peer_chain,omitempty"`
	VerifiedChain         []CertificateInfo   `json:"verified_chain,omitempty"`
	OCSPStapled           bool                `json:"ocsp_stapled"`
	OCSPResponseBytes     int                 `json:"ocsp_response_bytes,omitempty"`
	SCTCount              int                 `json:"sct_count"`
	VerificationError     string              `json:"verification_error,omitempty"`
	Error                 string              `json:"error,omitempty"`
	Findings              []Finding           `json:"findings,omitempty"`
	peerCertificates      []*x509.Certificate
	verifiedCertificates  []*x509.Certificate
}

type MailSecurity struct {
	MX           []string `json:"mx,omitempty"`
	SPF          []string `json:"spf,omitempty"`
	DMARC        []string `json:"dmarc,omitempty"`
	MTASTSRecord []string `json:"mta_sts_record,omitempty"`
	TLSReporting []string `json:"tls_reporting,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

type DNSRecordTTL struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type CAARecord struct {
	Name            string `json:"name"`
	TTL             uint32 `json:"ttl"`
	Flags           uint8  `json:"flags"`
	Tag             string `json:"tag"`
	Value           string `json:"value"`
	DNSSECValidated bool   `json:"dnssec_validated"`
}

type TLSARecord struct {
	Name                  string `json:"name"`
	TTL                   uint32 `json:"ttl"`
	CertificateUsage      uint8  `json:"certificate_usage"`
	Selector              uint8  `json:"selector"`
	MatchingType          uint8  `json:"matching_type"`
	AssociationData       string `json:"association_data"`
	MatchesPresentedChain bool   `json:"matches_presented_chain"`
	DNSSECValidated       bool   `json:"dnssec_validated"`
}

type HTTPSRecord struct {
	Name            string            `json:"name"`
	TTL             uint32            `json:"ttl"`
	Priority        uint16            `json:"priority"`
	TargetName      string            `json:"target_name"`
	Parameters      map[string]string `json:"parameters,omitempty"`
	DNSSECValidated bool              `json:"dnssec_validated"`
}

type NameserverRecord struct {
	Name      string   `json:"name"`
	TTL       uint32   `json:"ttl"`
	Addresses []string `json:"addresses,omitempty"`
}

type DSRecord struct {
	Name          string `json:"name"`
	TTL           uint32 `json:"ttl"`
	KeyTag        uint16 `json:"key_tag"`
	Algorithm     uint8  `json:"algorithm"`
	AlgorithmName string `json:"algorithm_name"`
	DigestType    uint8  `json:"digest_type"`
	Digest        string `json:"digest"`
}

type DNSKEYRecord struct {
	Name          string `json:"name"`
	TTL           uint32 `json:"ttl"`
	Flags         uint16 `json:"flags"`
	Protocol      uint8  `json:"protocol"`
	Algorithm     uint8  `json:"algorithm"`
	AlgorithmName string `json:"algorithm_name"`
	KeyTag        uint16 `json:"key_tag"`
}

type RRSIGRecord struct {
	Name          string    `json:"name"`
	TTL           uint32    `json:"ttl"`
	TypeCovered   string    `json:"type_covered"`
	Algorithm     uint8     `json:"algorithm"`
	AlgorithmName string    `json:"algorithm_name"`
	KeyTag        uint16    `json:"key_tag"`
	SignerName    string    `json:"signer_name"`
	Inception     time.Time `json:"inception"`
	Expiration    time.Time `json:"expiration"`
}

type DNSDetails struct {
	Resolver          string             `json:"resolver,omitempty"`
	DNSSECStatus      string             `json:"dnssec_status"`
	AuthenticatedData bool               `json:"authenticated_data"`
	Zone              string             `json:"zone,omitempty"`
	CNAMEChain        []string           `json:"cname_chain,omitempty"`
	RecordTTLs        []DNSRecordTTL     `json:"record_ttls,omitempty"`
	Nameservers       []NameserverRecord `json:"nameservers,omitempty"`
	CAA               []CAARecord        `json:"caa,omitempty"`
	TLSA              []TLSARecord       `json:"tlsa,omitempty"`
	HTTPS             []HTTPSRecord      `json:"https_records,omitempty"`
	DS                []DSRecord         `json:"ds,omitempty"`
	DNSKEY            []DNSKEYRecord     `json:"dnskey,omitempty"`
	RRSIG             []RRSIGRecord      `json:"rrsig,omitempty"`
	Errors            []string           `json:"errors,omitempty"`
}

type Result struct {
	SchemaVersion int `json:"schema_version"`

	// Original fields remain populated for compatibility with existing JSON users.
	Hostname   string    `json:"hostname"`
	CNAME      string    `json:"cname,omitempty"`
	IPs        []string  `json:"ips"`
	Reachable  bool      `json:"reachable"`
	TLSVersion string    `json:"tls_version,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	AltNames   []string  `json:"alt_names,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	Issued     time.Time `json:"issued,omitempty"`
	Expiry     time.Time `json:"expiry,omitempty"`
	Error      string    `json:"error,omitempty"`

	ARecords    []string         `json:"a_records,omitempty"`
	AAAARecords []string         `json:"aaaa_records,omitempty"`
	Endpoints   []EndpointResult `json:"endpoints,omitempty"`
	DNS         DNSDetails       `json:"dns"`
	Findings    []Finding        `json:"findings,omitempty"`
	Mail        *MailSecurity    `json:"mail,omitempty"`
	HTTP        *HTTPInspection  `json:"http,omitempty"`
}

type SchemaCapability struct {
	Name             string `json:"name"`
	EnabledByDefault bool   `json:"enabled_by_default"`
	Flag             string `json:"flag,omitempty"`
}

type SchemaCapabilities struct {
	SchemaVersion int                `json:"schema_version"`
	Capabilities  []SchemaCapability `json:"capabilities"`
}

type options struct {
	scanCiphers bool
	mail        bool
	dnsServer   string
	http        HTTPScanOptions
}

func main() {
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	markdownOutput := flag.Bool("markdown", false, "Output in Markdown format")
	hostFile := flag.String("file", "", "Read hostnames from a text file (one per line)")
	scanCiphers := flag.Bool("scan-ciphers", false, "Actively enumerate accepted TLS 1.0-1.2 cipher suites (slow)")
	mail := flag.Bool("mail", false, "Inspect MX, SPF, DMARC, MTA-STS, and TLS reporting")
	dnsServer := flag.String("dns-server", "", "DNS resolver for CAA, TLSA, HTTPS, TTL, and DNSSEC AD checks (default: system resolver)")
	httpEnabled := flag.Bool("http", false, "Enable bounded HTTP security inspection")
	var httpPaths httpPathList
	flag.Var(&httpPaths, "http-path", "HTTPS path to inspect (repeatable; default /)")
	httpTimeout := flag.Duration("http-timeout", 10*time.Second, "Timeout for each HTTP request")
	httpMaxRedirects := flag.Int("http-max-redirects", 10, "Maximum HTTP redirect hops")
	httpMaxBody := flag.Int64("http-max-body", 1<<20, "Maximum decoded response bytes to read and discard")
	var httpAllowedHosts httpHostnameList
	flag.Var(&httpAllowedHosts, "http-allow-redirect-host", "Allow redirects to this hostname (repeatable)")
	versionOutput := flag.Bool("version", false, "Print version information and exit")
	schemaCapabilitiesOutput := flag.Bool("schema-capabilities", false, "Print JSON schema capabilities and exit")
	flag.Parse()

	if *versionOutput {
		fmt.Printf("mpdc %s\n", version)
		return
	}
	if *schemaCapabilitiesOutput {
		if err := writeSchemaCapabilities(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding schema capabilities: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *jsonOutput && *markdownOutput {
		fmt.Fprintln(os.Stderr, "Error: -json and -markdown flags are mutually exclusive.")
		os.Exit(1)
	}
	if err := validateHTTPFlagValues(*httpTimeout, *httpMaxRedirects, *httpMaxBody, httpPaths); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	hostnames := flag.Args()

	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				hostnames = append(hostnames, strings.Fields(line)...)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
	}

	if *hostFile != "" {
		f, err := os.Open(*hostFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file %s: %v\n", *hostFile, err)
			os.Exit(1)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				hostnames = append(hostnames, strings.Fields(line)...)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", *hostFile, err)
			os.Exit(1)
		}
	}

	if len(hostnames) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: mpdc [options] <hostname>...")
		flag.Usage()
		os.Exit(1)
	}

	paths := []string(httpPaths)
	if len(paths) == 0 {
		paths = []string{"/"}
	}
	opts := options{
		scanCiphers: *scanCiphers,
		mail:        *mail,
		dnsServer:   *dnsServer,
		http: HTTPScanOptions{
			Enabled:              *httpEnabled,
			Paths:                paths,
			Timeout:              *httpTimeout,
			MaxRedirects:         *httpMaxRedirects,
			MaxBodyBytes:         *httpMaxBody,
			AllowedRedirectHosts: []string(httpAllowedHosts),
		},
	}
	results := make([]Result, 0, len(hostnames))
	for _, host := range hostnames {
		results = append(results, inspectHost(normalizeHostname(host), opts))
	}

	if *jsonOutput {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else if *markdownOutput {
		printMarkdown(results)
	} else {
		for _, result := range results {
			printResult(result)
		}
	}
}

func writeSchemaCapabilities(w io.Writer) error {
	capabilities := SchemaCapabilities{
		SchemaVersion: jsonSchemaVersion,
		Capabilities: []SchemaCapability{
			{Name: "dns", EnabledByDefault: true},
			{Name: "tls", EnabledByDefault: true},
			{Name: "mail", Flag: "-mail"},
			{Name: "http", Flag: "-http"},
		},
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(capabilities)
}

func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.TrimSpace(host), ".")
}

func inspectHost(host string, opts options) Result {
	result := Result{SchemaVersion: jsonSchemaVersion, Hostname: host}
	if host == "" {
		result.Error = "empty hostname"
		result.Findings = append(result.Findings, finding("INPUT_INVALID", "critical", "The hostname is empty."))
		return result
	}

	cname, err := net.LookupCNAME(host)
	if err == nil {
		cname = normalizeHostname(cname)
		if !strings.EqualFold(cname, host) {
			result.CNAME = cname
		}
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		result.Error = fmt.Sprintf("DNS lookup failed: %v", err)
		result.Findings = append(result.Findings, finding("DNS_LOOKUP_FAILED", "critical", result.Error))
		result.DNS = inspectAdvancedDNS(host, opts.dnsServer, nil)
		addDNSFindings(&result)
		if len(result.DNS.CNAMEChain) > 0 && len(result.DNS.RecordTTLs) == len(result.DNS.CNAMEChain) {
			result.Findings = append(result.Findings, finding(
				"POSSIBLE_DANGLING_CNAME", "warning",
				"The CNAME chain did not produce an address. This is a risk indicator, not proof that the target is claimable."))
		}
		if opts.mail {
			result.Mail = inspectMailSecurity(host)
		}
		addHTTPInspection(&result, opts.http)
		return result
	}

	seen := make(map[string]bool)
	for _, ip := range ips {
		value := ip.String()
		if seen[value] {
			continue
		}
		seen[value] = true
		result.IPs = append(result.IPs, value)
		if ip.To4() != nil {
			result.ARecords = append(result.ARecords, value)
		} else {
			result.AAAARecords = append(result.AAAARecords, value)
		}
	}
	sort.Strings(result.ARecords)
	sort.Strings(result.AAAARecords)
	result.IPs = append(append([]string{}, result.ARecords...), result.AAAARecords...)

	result.Endpoints = inspectEndpoints(host, result.IPs, opts.scanCiphers)
	for i := range result.Endpoints {
		endpoint := &result.Endpoints[i]
		if endpoint.TLSHandshake {
			result.Reachable = true
		}
		if endpoint.IPClassification != "public" {
			result.Findings = append(result.Findings, finding(
				"DNS_NON_PUBLIC_ADDRESS",
				"info",
				fmt.Sprintf("%s resolves to %s address %s.", host, endpoint.IPClassification, endpoint.IP),
			))
		}
		result.Findings = append(result.Findings, endpoint.Findings...)
	}
	addConsistencyFindings(&result)
	result.DNS = inspectAdvancedDNS(host, opts.dnsServer, result.Endpoints)
	addDNSFindings(&result)
	populateCompatibilityFields(&result)

	if opts.mail {
		result.Mail = inspectMailSecurity(host)
	}
	addHTTPInspection(&result, opts.http)
	return result
}

func inspectEndpoints(host string, ips []string, scanCiphers bool) []EndpointResult {
	results := make([]EndpointResult, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(index int, address string) {
			defer wg.Done()
			results[index] = inspectEndpoint(host, address, scanCiphers)
		}(i, ip)
	}
	wg.Wait()
	return results
}

func inspectEndpoint(host, ip string, scanCiphers bool) EndpointResult {
	endpoint := EndpointResult{
		IP:               ip,
		AddressFamily:    addressFamily(ip),
		IPClassification: classifyIP(ip),
	}

	verifiedState, tcpReachable, err := connectTLS(host, ip, &tls.Config{
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

		diagnosticState, diagnosticTCP, diagnosticErr := connectTLS(host, ip, &tls.Config{
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

	endpoint.SupportedTLSVersions = scanTLSVersions(host, ip)
	if scanCiphers {
		endpoint.SupportedCipherSuites = scanCipherSuites(host, ip)
	}
	addEndpointFindings(&endpoint)
	return endpoint
}

func connectTLS(host, ip string, config *tls.Config) (tls.ConnectionState, bool, error) {
	var empty tls.ConnectionState
	dialer := &net.Dialer{Timeout: connectionTimeout}
	raw, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return empty, false, err
	}

	deadline := time.Now().Add(connectionTimeout)
	if err := raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return empty, true, err
	}

	conn := tls.Client(raw, config)
	if err := conn.Handshake(); err != nil {
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

func certificateInfo(cert *x509.Certificate, now time.Time) CertificateInfo {
	sum := sha256.Sum256(cert.Raw)
	info := CertificateInfo{
		Subject:                cert.Subject.String(),
		Issuer:                 cert.Issuer.String(),
		AltNames:               append([]string(nil), cert.DNSNames...),
		Issued:                 cert.NotBefore,
		Expiry:                 cert.NotAfter,
		DaysRemaining:          daysRemaining(now, cert.NotAfter),
		TimeStatus:             certificateTimeStatus(cert, now),
		SerialNumber:           strings.ToUpper(cert.SerialNumber.Text(16)),
		FingerprintSHA256:      colonHex(sum[:]),
		PublicKeyAlgorithm:     cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm:     cert.SignatureAlgorithm.String(),
		KeyUsage:               keyUsageStrings(cert.KeyUsage),
		ExtendedKeyUsage:       extendedKeyUsageStrings(cert.ExtKeyUsage),
		IsCA:                   cert.IsCA,
		OCSPServers:            append([]string(nil), cert.OCSPServer...),
		CRLDistributionPoints:  append([]string(nil), cert.CRLDistributionPoints...),
		IssuingCertificateURLs: append([]string(nil), cert.IssuingCertificateURL...),
	}
	for _, name := range cert.DNSNames {
		if strings.HasPrefix(name, "*.") {
			info.WildcardAltNames = append(info.WildcardAltNames, name)
		}
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyBits = key.Curve.Params().BitSize
		info.PublicKeyCurve = key.Curve.Params().Name
	case ed25519.PublicKey:
		info.PublicKeyBits = len(key) * 8
	}
	tlsFeatureOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(tlsFeatureOID) {
			continue
		}
		var features []int
		if _, err := asn1.Unmarshal(extension.Value, &features); err == nil {
			info.TLSFeatures = features
			for _, feature := range features {
				if feature == 5 {
					info.MustStaple = true
				}
			}
		}
	}
	return info
}

func scanTLSVersions(host, ip string) []string {
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
		if _, _, err := connectTLS(host, ip, config); err == nil {
			supported = append(supported, version.name)
		}
	}
	return supported
}

func scanCipherSuites(host, ip string) map[string][]string {
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
		for _, suite := range suites {
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
			if _, _, err := connectTLS(host, ip, config); err == nil {
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

func addEndpointFindings(endpoint *EndpointResult) {
	if !endpoint.TCPReachable {
		if isLocalNetworkUnavailable(endpoint.Error) {
			endpoint.Findings = append(endpoint.Findings, finding(
				"LOCAL_NETWORK_UNAVAILABLE", "info",
				fmt.Sprintf("%s could not be tested from this machine because there is no usable network route.", endpoint.IP)))
			return
		}
		endpoint.Findings = append(endpoint.Findings, finding(
			"HTTPS_UNREACHABLE", "critical", fmt.Sprintf("%s:443 is unreachable.", endpoint.IP)))
		return
	}
	if !endpoint.TLSHandshake {
		endpoint.Findings = append(endpoint.Findings, finding(
			"TLS_HANDSHAKE_FAILED", "critical", fmt.Sprintf("%s did not complete a TLS handshake.", endpoint.IP)))
		return
	}
	if endpoint.Certificate != nil {
		cert := endpoint.Certificate
		switch cert.TimeStatus {
		case "expired":
			endpoint.Findings = append(endpoint.Findings, finding(
				"CERT_EXPIRED", "critical", fmt.Sprintf("The certificate on %s has expired.", endpoint.IP)))
		case "not_yet_valid":
			endpoint.Findings = append(endpoint.Findings, finding(
				"CERT_NOT_YET_VALID", "critical", fmt.Sprintf("The certificate on %s is not yet valid.", endpoint.IP)))
		case "valid":
			switch {
			case cert.DaysRemaining <= 14:
				endpoint.Findings = append(endpoint.Findings, finding(
					"CERT_EXPIRES_SOON", "critical",
					fmt.Sprintf("The certificate on %s expires in %d days.", endpoint.IP, cert.DaysRemaining)))
			case cert.DaysRemaining <= 30:
				endpoint.Findings = append(endpoint.Findings, finding(
					"CERT_EXPIRES_SOON", "warning",
					fmt.Sprintf("The certificate on %s expires in %d days.", endpoint.IP, cert.DaysRemaining)))
			case cert.DaysRemaining <= 60:
				endpoint.Findings = append(endpoint.Findings, finding(
					"CERT_EXPIRY_APPROACHING", "info",
					fmt.Sprintf("The certificate on %s expires in %d days.", endpoint.IP, cert.DaysRemaining)))
			}
		}
		if !endpoint.HostnameMatch {
			endpoint.Findings = append(endpoint.Findings, finding(
				"CERT_HOSTNAME_MISMATCH", "critical",
				fmt.Sprintf("The certificate on %s does not cover the requested hostname.", endpoint.IP)))
		}
		if !endpoint.ChainTrusted {
			endpoint.Findings = append(endpoint.Findings, finding(
				"CERT_UNTRUSTED", "critical",
				fmt.Sprintf("The certificate chain on %s is not trusted by the system trust store.", endpoint.IP)))
		}
		if cert.PublicKeyAlgorithm == x509.RSA.String() && cert.PublicKeyBits > 0 && cert.PublicKeyBits < 2048 {
			endpoint.Findings = append(endpoint.Findings, finding(
				"CERT_WEAK_RSA_KEY", "critical",
				fmt.Sprintf("The certificate on %s uses a %d-bit RSA key.", endpoint.IP, cert.PublicKeyBits)))
		}
		signature := strings.ToUpper(cert.SignatureAlgorithm)
		if strings.Contains(signature, "MD5") || strings.Contains(signature, "SHA1") {
			endpoint.Findings = append(endpoint.Findings, finding(
				"CERT_WEAK_SIGNATURE", "critical",
				fmt.Sprintf("The certificate on %s uses %s.", endpoint.IP, cert.SignatureAlgorithm)))
		}
		if cert.MustStaple && !endpoint.OCSPStapled {
			endpoint.Findings = append(endpoint.Findings, finding(
				"CERT_MUST_STAPLE_MISSING", "critical",
				fmt.Sprintf("The certificate on %s requires an OCSP staple, but none was presented.", endpoint.IP)))
		}
	}
	if containsString(endpoint.SupportedTLSVersions, "TLS 1.0") ||
		containsString(endpoint.SupportedTLSVersions, "TLS 1.1") {
		endpoint.Findings = append(endpoint.Findings, finding(
			"TLS_LEGACY_VERSION_SUPPORTED", "critical",
			fmt.Sprintf("%s supports an obsolete TLS protocol version.", endpoint.IP)))
	}
	for version, suites := range endpoint.SupportedCipherSuites {
		for _, suite := range suites {
			upper := strings.ToUpper(suite)
			if strings.Contains(upper, "RC4") || strings.Contains(upper, "3DES") ||
				strings.Contains(upper, "_NULL_") {
				endpoint.Findings = append(endpoint.Findings, finding(
					"TLS_WEAK_CIPHER_SUPPORTED", "critical",
					fmt.Sprintf("%s accepts weak cipher %s under %s.", endpoint.IP, suite, version)))
			}
		}
	}
}

func addConsistencyFindings(result *Result) {
	fingerprints := make(map[string][]string)
	versionSets := make(map[string][]string)
	for _, endpoint := range result.Endpoints {
		if !endpoint.TLSHandshake {
			continue
		}
		if endpoint.Certificate != nil {
			fingerprints[endpoint.Certificate.FingerprintSHA256] =
				append(fingerprints[endpoint.Certificate.FingerprintSHA256], endpoint.IP)
		}
		key := strings.Join(endpoint.SupportedTLSVersions, ",")
		versionSets[key] = append(versionSets[key], endpoint.IP)
	}
	if len(fingerprints) > 1 {
		result.Findings = append(result.Findings, finding(
			"ENDPOINT_CERT_MISMATCH", "warning",
			"Resolved endpoints present different leaf certificates. This can be intentional, but should be verified."))
	}
	if len(versionSets) > 1 {
		result.Findings = append(result.Findings, finding(
			"ENDPOINT_TLS_POLICY_MISMATCH", "warning",
			"Resolved endpoints support different TLS protocol versions."))
	}

	hasPublic := false
	hasNonPublic := false
	for _, endpoint := range result.Endpoints {
		if endpoint.IPClassification == "public" {
			hasPublic = true
		} else {
			hasNonPublic = true
		}
	}
	if hasPublic && hasNonPublic {
		result.Findings = append(result.Findings, finding(
			"DNS_MIXED_PUBLIC_PRIVATE", "warning",
			"The hostname resolves to both public and non-public addresses."))
	}
}

func populateCompatibilityFields(result *Result) {
	for _, endpoint := range result.Endpoints {
		if endpoint.Certificate == nil {
			continue
		}
		result.TLSVersion = endpoint.TLSVersion
		result.Subject = endpoint.Certificate.Subject
		result.AltNames = append([]string(nil), endpoint.Certificate.AltNames...)
		result.Issuer = endpoint.Certificate.Issuer
		result.Issued = endpoint.Certificate.Issued
		result.Expiry = endpoint.Certificate.Expiry
		if endpoint.Error != "" {
			result.Error = endpoint.Error
		}
		return
	}
	if len(result.Endpoints) > 0 {
		result.Error = result.Endpoints[0].Error
	}
}

const (
	dnsTypeA      = 1
	dnsTypeNS     = 2
	dnsTypeCNAME  = 5
	dnsTypeSOA    = 6
	dnsTypeAAAA   = 28
	dnsTypeDS     = 43
	dnsTypeRRSIG  = 46
	dnsTypeDNSKEY = 48
	dnsTypeTLSA   = 52
	dnsTypeHTTPS  = 65
	dnsTypeCAA    = 257
)

type dnsWireRecord struct {
	name       string
	recordType uint16
	ttl        uint32
	data       []byte
	dataOffset int
	dataEnd    int
	message    []byte
}

type dnsWireResponse struct {
	authenticatedData bool
	truncated         bool
	responseCode      int
	answers           []dnsWireRecord
	authority         []dnsWireRecord
}

func inspectAdvancedDNS(host, configuredResolver string, endpoints []EndpointResult) DNSDetails {
	details := DNSDetails{DNSSECStatus: "unavailable"}
	resolver, err := dnsResolverAddress(configuredResolver)
	if err != nil {
		details.Errors = append(details.Errors, err.Error())
		return details
	}
	details.Resolver = resolver

	aResponse, aErr := dnsQuery(resolver, host, dnsTypeA)
	aaaaResponse, aaaaErr := dnsQuery(resolver, host, dnsTypeAAAA)
	if aErr != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("A query: %v", aErr))
	}
	if aaaaErr != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("AAAA query: %v", aaaaErr))
	}
	if aErr == nil || aaaaErr == nil {
		details.AuthenticatedData = (aErr == nil && aResponse.authenticatedData) ||
			(aaaaErr == nil && aaaaResponse.authenticatedData)
		if details.AuthenticatedData {
			details.DNSSECStatus = "resolver_validated"
		} else {
			details.DNSSECStatus = "not_validated"
		}
	}

	cnameLinks := make(map[string]string)
	for _, response := range []dnsWireResponse{aResponse, aaaaResponse} {
		for _, record := range response.answers {
			switch record.recordType {
			case dnsTypeA:
				if len(record.data) == net.IPv4len {
					details.RecordTTLs = append(details.RecordTTLs, DNSRecordTTL{
						Type: "A", Name: record.name, Value: net.IP(record.data).String(), TTL: record.ttl,
					})
				}
			case dnsTypeAAAA:
				if len(record.data) == net.IPv6len {
					details.RecordTTLs = append(details.RecordTTLs, DNSRecordTTL{
						Type: "AAAA", Name: record.name, Value: net.IP(record.data).String(), TTL: record.ttl,
					})
				}
			case dnsTypeCNAME:
				target, _, nameErr := readDNSName(record.message, record.dataOffset)
				if nameErr == nil {
					cnameLinks[normalizeHostname(record.name)] = normalizeHostname(target)
					details.RecordTTLs = append(details.RecordTTLs, DNSRecordTTL{
						Type: "CNAME", Name: record.name, Value: normalizeHostname(target), TTL: record.ttl,
					})
				}
			case dnsTypeRRSIG:
				if parsed, ok := parseRRSIGRecord(record); ok {
					details.RRSIG = append(details.RRSIG, parsed)
				}
			}
		}
	}
	details.CNAMEChain = buildCNAMEChain(host, cnameLinks)
	sort.Slice(details.RecordTTLs, func(i, j int) bool {
		left, right := details.RecordTTLs[i], details.RecordTTLs[j]
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.Value < right.Value
	})

	caa, caaErr := lookupRelevantCAA(resolver, host)
	if caaErr != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("CAA query: %v", caaErr))
	} else {
		details.CAA = caa
	}

	tlsaName := "_443._tcp." + host
	tlsaResponse, tlsaErr := dnsQuery(resolver, tlsaName, dnsTypeTLSA)
	if tlsaErr != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("TLSA query: %v", tlsaErr))
	} else {
		for _, record := range tlsaResponse.answers {
			parsed, ok := parseTLSARecord(record)
			if !ok {
				continue
			}
			parsed.DNSSECValidated = tlsaResponse.authenticatedData
			parsed.MatchesPresentedChain = tlsaMatchesEndpoints(parsed, endpoints)
			details.TLSA = append(details.TLSA, parsed)
		}
	}

	httpsResponse, httpsErr := dnsQuery(resolver, host, dnsTypeHTTPS)
	if httpsErr != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("HTTPS query: %v", httpsErr))
	} else {
		for _, record := range httpsResponse.answers {
			parsed, ok := parseHTTPSRecord(record)
			if ok {
				parsed.DNSSECValidated = httpsResponse.authenticatedData
				details.HTTPS = append(details.HTTPS, parsed)
			}
		}
	}
	inspectDNSSECZone(resolver, host, &details)
	return details
}

func addDNSFindings(result *Result) {
	if result.DNS.DNSSECStatus == "not_validated" {
		result.Findings = append(result.Findings, finding(
			"DNSSEC_NOT_VALIDATED", "info",
			"The selected resolver did not authenticate the address response with DNSSEC. This does not distinguish an unsigned zone from a non-validating resolver."))
	}
	if len(result.DNS.TLSA) > 0 {
		validated := false
		matched := false
		for _, record := range result.DNS.TLSA {
			validated = validated || record.DNSSECValidated
			matched = matched || record.MatchesPresentedChain
		}
		if validated && !matched {
			result.Findings = append(result.Findings, finding(
				"DANE_TLSA_MISMATCH", "critical",
				"DNSSEC-validated TLSA records do not match the presented certificate chain."))
		} else if !validated {
			result.Findings = append(result.Findings, finding(
				"DANE_TLSA_NOT_VALIDATED", "info",
				"TLSA records were found but were not authenticated by the selected resolver."))
		}
	}
	if result.DNS.Zone != "" && len(result.DNS.Nameservers) < 2 {
		result.Findings = append(result.Findings, finding(
			"DNS_SINGLE_NAMESERVER", "warning",
			fmt.Sprintf("DNS zone %s exposes fewer than two nameservers.", result.DNS.Zone)))
	}
	for _, record := range result.DNS.DS {
		if record.Algorithm == 5 || record.Algorithm == 7 || record.DigestType == 1 {
			result.Findings = append(result.Findings, finding(
				"DNSSEC_LEGACY_ALGORITHM", "warning",
				fmt.Sprintf("DS key tag %d uses legacy algorithm %s or SHA-1 digest type.", record.KeyTag, record.AlgorithmName)))
		}
	}
	now := time.Now()
	for _, record := range result.DNS.RRSIG {
		if now.After(record.Expiration) {
			result.Findings = append(result.Findings, finding(
				"DNSSEC_SIGNATURE_EXPIRED", "critical",
				fmt.Sprintf("The %s RRSIG for %s expired at %s.", record.TypeCovered, record.Name, record.Expiration.Format(time.RFC3339))))
		}
	}
}

func inspectDNSSECZone(resolver, host string, details *DNSDetails) {
	soaResponse, err := dnsQuery(resolver, host, dnsTypeSOA)
	if err != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("SOA query: %v", err))
		return
	}
	zone := ""
	for _, record := range append(soaResponse.answers, soaResponse.authority...) {
		if record.recordType == dnsTypeSOA {
			zone = record.name
			break
		}
	}
	if zone == "" {
		return
	}
	details.Zone = zone

	nsResponse, err := dnsQuery(resolver, zone, dnsTypeNS)
	if err != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("NS query: %v", err))
	} else {
		for _, record := range nsResponse.answers {
			if record.recordType != dnsTypeNS {
				continue
			}
			target, _, nameErr := readDNSName(record.message, record.dataOffset)
			if nameErr != nil {
				continue
			}
			entry := NameserverRecord{Name: normalizeHostname(target), TTL: record.ttl}
			if addresses, lookupErr := net.LookupHost(entry.Name); lookupErr == nil {
				entry.Addresses = append(entry.Addresses, addresses...)
				sort.Strings(entry.Addresses)
			}
			details.Nameservers = append(details.Nameservers, entry)
		}
	}

	dsResponse, err := dnsQuery(resolver, zone, dnsTypeDS)
	if err != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("DS query: %v", err))
	} else {
		for _, record := range dsResponse.answers {
			if parsed, ok := parseDSRecord(record); ok {
				details.DS = append(details.DS, parsed)
			}
			if parsed, ok := parseRRSIGRecord(record); ok {
				details.RRSIG = append(details.RRSIG, parsed)
			}
		}
	}

	keyResponse, err := dnsQuery(resolver, zone, dnsTypeDNSKEY)
	if err != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("DNSKEY query: %v", err))
	} else {
		for _, record := range keyResponse.answers {
			if parsed, ok := parseDNSKEYRecord(record); ok {
				details.DNSKEY = append(details.DNSKEY, parsed)
			}
			if parsed, ok := parseRRSIGRecord(record); ok {
				details.RRSIG = append(details.RRSIG, parsed)
			}
		}
	}
	sort.Slice(details.Nameservers, func(i, j int) bool {
		return details.Nameservers[i].Name < details.Nameservers[j].Name
	})
	sort.Slice(details.RRSIG, func(i, j int) bool {
		if details.RRSIG[i].Name != details.RRSIG[j].Name {
			return details.RRSIG[i].Name < details.RRSIG[j].Name
		}
		return details.RRSIG[i].TypeCovered < details.RRSIG[j].TypeCovered
	})
}

func parseDSRecord(record dnsWireRecord) (DSRecord, bool) {
	if record.recordType != dnsTypeDS || len(record.data) < 4 {
		return DSRecord{}, false
	}
	return DSRecord{
		Name:          record.name,
		TTL:           record.ttl,
		KeyTag:        binary.BigEndian.Uint16(record.data[:2]),
		Algorithm:     record.data[2],
		AlgorithmName: dnssecAlgorithmName(record.data[2]),
		DigestType:    record.data[3],
		Digest:        strings.ToUpper(hex.EncodeToString(record.data[4:])),
	}, true
}

func parseDNSKEYRecord(record dnsWireRecord) (DNSKEYRecord, bool) {
	if record.recordType != dnsTypeDNSKEY || len(record.data) < 4 {
		return DNSKEYRecord{}, false
	}
	return DNSKEYRecord{
		Name:          record.name,
		TTL:           record.ttl,
		Flags:         binary.BigEndian.Uint16(record.data[:2]),
		Protocol:      record.data[2],
		Algorithm:     record.data[3],
		AlgorithmName: dnssecAlgorithmName(record.data[3]),
		KeyTag:        dnskeyTag(record.data),
	}, true
}

func parseRRSIGRecord(record dnsWireRecord) (RRSIGRecord, bool) {
	if record.recordType != dnsTypeRRSIG || len(record.data) < 18 {
		return RRSIGRecord{}, false
	}
	signer, _, err := readDNSName(record.message, record.dataOffset+18)
	if err != nil {
		return RRSIGRecord{}, false
	}
	algorithm := record.data[2]
	return RRSIGRecord{
		Name:          record.name,
		TTL:           record.ttl,
		TypeCovered:   dnsTypeName(binary.BigEndian.Uint16(record.data[:2])),
		Algorithm:     algorithm,
		AlgorithmName: dnssecAlgorithmName(algorithm),
		KeyTag:        binary.BigEndian.Uint16(record.data[16:18]),
		SignerName:    normalizeHostname(signer),
		Expiration:    time.Unix(int64(binary.BigEndian.Uint32(record.data[8:12])), 0).UTC(),
		Inception:     time.Unix(int64(binary.BigEndian.Uint32(record.data[12:16])), 0).UTC(),
	}, true
}

func dnskeyTag(data []byte) uint16 {
	var accumulator uint32
	for index, value := range data {
		if index&1 == 0 {
			accumulator += uint32(value) << 8
		} else {
			accumulator += uint32(value)
		}
	}
	accumulator += (accumulator >> 16) & 0xffff
	return uint16(accumulator & 0xffff)
}

func dnssecAlgorithmName(algorithm uint8) string {
	switch algorithm {
	case 5:
		return "RSASHA1"
	case 7:
		return "RSASHA1-NSEC3-SHA1"
	case 8:
		return "RSASHA256"
	case 10:
		return "RSASHA512"
	case 13:
		return "ECDSAP256SHA256"
	case 14:
		return "ECDSAP384SHA384"
	case 15:
		return "ED25519"
	case 16:
		return "ED448"
	default:
		return fmt.Sprintf("algorithm-%d", algorithm)
	}
}

func dnsTypeName(recordType uint16) string {
	switch recordType {
	case dnsTypeA:
		return "A"
	case dnsTypeNS:
		return "NS"
	case dnsTypeCNAME:
		return "CNAME"
	case dnsTypeSOA:
		return "SOA"
	case dnsTypeAAAA:
		return "AAAA"
	case dnsTypeDS:
		return "DS"
	case dnsTypeRRSIG:
		return "RRSIG"
	case dnsTypeDNSKEY:
		return "DNSKEY"
	case dnsTypeTLSA:
		return "TLSA"
	case dnsTypeHTTPS:
		return "HTTPS"
	case dnsTypeCAA:
		return "CAA"
	default:
		return strconv.Itoa(int(recordType))
	}
}

func dnsResolverAddress(configured string) (string, error) {
	if configured != "" {
		return ensureDNSPort(configured), nil
	}
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("cannot determine DNS resolver: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && strings.EqualFold(fields[0], "nameserver") {
			return ensureDNSPort(fields[1]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("cannot read DNS resolver configuration: %w", err)
	}
	return "", errors.New("no nameserver found in /etc/resolv.conf; use --dns-server")
}

func ensureDNSPort(address string) string {
	address = strings.TrimSpace(address)
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	if parsed := net.ParseIP(address); parsed != nil {
		return net.JoinHostPort(address, "53")
	}
	if strings.Count(address, ":") > 1 {
		return net.JoinHostPort(address, "53")
	}
	return net.JoinHostPort(address, "53")
}

func dnsQuery(resolver, name string, recordType uint16) (dnsWireResponse, error) {
	var empty dnsWireResponse
	query, id, err := buildDNSQuery(name, recordType)
	if err != nil {
		return empty, err
	}

	responseBytes, err := exchangeDNSUDP(resolver, query)
	if err != nil {
		return empty, err
	}
	response, err := parseDNSResponse(responseBytes, id)
	if err != nil {
		return empty, err
	}
	if response.truncated {
		responseBytes, err = exchangeDNSTCP(resolver, query)
		if err != nil {
			return empty, err
		}
		response, err = parseDNSResponse(responseBytes, id)
		if err != nil {
			return empty, err
		}
	}
	switch response.responseCode {
	case 0, 3:
		return response, nil
	case 2:
		return response, errors.New("resolver returned SERVFAIL (possible DNSSEC failure or transient resolver error)")
	default:
		return response, fmt.Errorf("resolver returned DNS response code %d", response.responseCode)
	}
}

func buildDNSQuery(name string, recordType uint16) ([]byte, uint16, error) {
	name = normalizeHostname(name)
	var random [2]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(random[:])
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100) // Recursion desired.
	binary.BigEndian.PutUint16(message[4:6], 1)
	binary.BigEndian.PutUint16(message[10:12], 1) // One OPT pseudo-record.

	encodedName, err := encodeDNSName(name)
	if err != nil {
		return nil, 0, err
	}
	message = append(message, encodedName...)
	message = binary.BigEndian.AppendUint16(message, recordType)
	message = binary.BigEndian.AppendUint16(message, 1)

	// EDNS(0), 1232-byte UDP payload, with the DNSSEC OK bit set.
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, 41)
	message = binary.BigEndian.AppendUint16(message, 1232)
	message = binary.BigEndian.AppendUint32(message, 0x00008000)
	message = binary.BigEndian.AppendUint16(message, 0)
	return message, id, nil
}

func encodeDNSName(name string) ([]byte, error) {
	if name == "" {
		return []byte{0}, nil
	}
	var encoded []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label in %q", name)
		}
		if len(encoded)+len(label)+2 > 255 {
			return nil, fmt.Errorf("DNS name is too long: %q", name)
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0), nil
}

func exchangeDNSUDP(resolver string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", resolver, connectionTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(connectionTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:n], nil
}

func exchangeDNSTCP(resolver string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", resolver, connectionTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(connectionTimeout)); err != nil {
		return nil, err
	}
	frame := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	frame = append(frame, query...)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	lengthBytes := make([]byte, 2)
	if _, err := ioReadFull(conn, lengthBytes); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes))
	response := make([]byte, length)
	if _, err := ioReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func ioReadFull(reader net.Conn, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		n, err := reader.Read(buffer[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, errors.New("unexpected end of DNS TCP response")
		}
	}
	return total, nil
}

func parseDNSResponse(message []byte, expectedID uint16) (dnsWireResponse, error) {
	var response dnsWireResponse
	if len(message) < 12 {
		return response, errors.New("short DNS response")
	}
	if binary.BigEndian.Uint16(message[0:2]) != expectedID {
		return response, errors.New("DNS response ID does not match query")
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 == 0 {
		return response, errors.New("DNS packet is not a response")
	}
	response.truncated = flags&0x0200 != 0
	response.authenticatedData = flags&0x0020 != 0
	response.responseCode = int(flags & 0x000f)
	questionCount := int(binary.BigEndian.Uint16(message[4:6]))
	answerCount := int(binary.BigEndian.Uint16(message[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(message[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(message[10:12]))

	offset := 12
	for i := 0; i < questionCount; i++ {
		_, next, err := readDNSName(message, offset)
		if err != nil {
			return response, err
		}
		offset = next
		if offset+4 > len(message) {
			return response, errors.New("truncated DNS question")
		}
		offset += 4
	}

	totalRecords := answerCount + authorityCount + additionalCount
	for i := 0; i < totalRecords; i++ {
		record, next, err := readDNSRecord(message, offset)
		if err != nil {
			return response, err
		}
		offset = next
		if i < answerCount {
			response.answers = append(response.answers, record)
		} else if i < answerCount+authorityCount {
			response.authority = append(response.authority, record)
		}
	}
	return response, nil
}

func readDNSRecord(message []byte, offset int) (dnsWireRecord, int, error) {
	var record dnsWireRecord
	name, next, err := readDNSName(message, offset)
	if err != nil {
		return record, offset, err
	}
	if next+10 > len(message) {
		return record, offset, errors.New("truncated DNS resource record")
	}
	recordType := binary.BigEndian.Uint16(message[next : next+2])
	ttl := binary.BigEndian.Uint32(message[next+4 : next+8])
	length := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
	dataOffset := next + 10
	dataEnd := dataOffset + length
	if dataEnd > len(message) {
		return record, offset, errors.New("truncated DNS resource data")
	}
	record = dnsWireRecord{
		name:       normalizeHostname(name),
		recordType: recordType,
		ttl:        ttl,
		data:       message[dataOffset:dataEnd],
		dataOffset: dataOffset,
		dataEnd:    dataEnd,
		message:    message,
	}
	return record, dataEnd, nil
}

func readDNSName(message []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(message) {
		return "", offset, errors.New("DNS name offset is outside the message")
	}
	var labels []string
	next := -1
	position := offset
	visited := make(map[int]bool)
	for steps := 0; steps < 128; steps++ {
		if position >= len(message) {
			return "", offset, errors.New("truncated DNS name")
		}
		if visited[position] {
			return "", offset, errors.New("DNS compression pointer loop")
		}
		visited[position] = true
		length := int(message[position])
		switch {
		case length == 0:
			if next < 0 {
				next = position + 1
			}
			return strings.Join(labels, "."), next, nil
		case length&0xc0 == 0xc0:
			if position+1 >= len(message) {
				return "", offset, errors.New("truncated DNS compression pointer")
			}
			if next < 0 {
				next = position + 2
			}
			position = int(binary.BigEndian.Uint16(message[position:position+2]) & 0x3fff)
		case length&0xc0 != 0:
			return "", offset, errors.New("invalid DNS label encoding")
		default:
			position++
			if position+length > len(message) {
				return "", offset, errors.New("truncated DNS label")
			}
			labels = append(labels, string(message[position:position+length]))
			position += length
		}
	}
	return "", offset, errors.New("DNS name exceeds compression traversal limit")
}

func buildCNAMEChain(host string, links map[string]string) []string {
	current := normalizeHostname(host)
	visited := make(map[string]bool)
	var chain []string
	for {
		target, ok := links[current]
		if !ok {
			return chain
		}
		if visited[current] {
			return append(chain, "[loop]")
		}
		visited[current] = true
		chain = append(chain, target)
		current = target
	}
}

func lookupRelevantCAA(resolver, host string) ([]CAARecord, error) {
	labels := strings.Split(normalizeHostname(host), ".")
	for i := 0; i < len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		response, err := dnsQuery(resolver, name, dnsTypeCAA)
		if err != nil {
			return nil, err
		}
		var records []CAARecord
		for _, record := range response.answers {
			if parsed, ok := parseCAARecord(record); ok {
				parsed.DNSSECValidated = response.authenticatedData
				records = append(records, parsed)
			}
		}
		if len(records) > 0 {
			return records, nil
		}
	}
	return nil, nil
}

func parseCAARecord(record dnsWireRecord) (CAARecord, bool) {
	if record.recordType != dnsTypeCAA || len(record.data) < 2 {
		return CAARecord{}, false
	}
	tagLength := int(record.data[1])
	if 2+tagLength > len(record.data) || tagLength == 0 {
		return CAARecord{}, false
	}
	return CAARecord{
		Name:  record.name,
		TTL:   record.ttl,
		Flags: record.data[0],
		Tag:   strings.ToLower(string(record.data[2 : 2+tagLength])),
		Value: string(record.data[2+tagLength:]),
	}, true
}

func parseTLSARecord(record dnsWireRecord) (TLSARecord, bool) {
	if record.recordType != dnsTypeTLSA || len(record.data) < 3 {
		return TLSARecord{}, false
	}
	return TLSARecord{
		Name:             record.name,
		TTL:              record.ttl,
		CertificateUsage: record.data[0],
		Selector:         record.data[1],
		MatchingType:     record.data[2],
		AssociationData:  strings.ToUpper(hex.EncodeToString(record.data[3:])),
	}, true
}

func tlsaMatchesEndpoints(record TLSARecord, endpoints []EndpointResult) bool {
	association, err := hex.DecodeString(record.AssociationData)
	if err != nil {
		return false
	}
	for _, endpoint := range endpoints {
		var candidates []*x509.Certificate
		if record.CertificateUsage == 1 || record.CertificateUsage == 3 {
			if len(endpoint.peerCertificates) > 0 &&
				tlsaMatchesCertificate(record, association, endpoint.peerCertificates[0]) {
				return true
			}
			continue
		}
		candidates = endpoint.verifiedCertificates
		if len(candidates) == 0 {
			candidates = endpoint.peerCertificates
		}
		for _, cert := range candidates {
			if tlsaMatchesCertificate(record, association, cert) {
				return true
			}
		}
	}
	return false
}

func tlsaMatchesCertificate(record TLSARecord, association []byte, cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	var selected []byte
	switch record.Selector {
	case 0:
		selected = cert.Raw
	case 1:
		selected = cert.RawSubjectPublicKeyInfo
	default:
		return false
	}
	switch record.MatchingType {
	case 0:
		return bytes.Equal(selected, association)
	case 1:
		sum := sha256.Sum256(selected)
		return bytes.Equal(sum[:], association)
	case 2:
		sum := sha512.Sum512(selected)
		return bytes.Equal(sum[:], association)
	default:
		return false
	}
}

func parseHTTPSRecord(record dnsWireRecord) (HTTPSRecord, bool) {
	if record.recordType != dnsTypeHTTPS || len(record.data) < 3 {
		return HTTPSRecord{}, false
	}
	priority := binary.BigEndian.Uint16(record.data[:2])
	target, next, err := readDNSName(record.message, record.dataOffset+2)
	if err != nil || next > record.dataEnd {
		return HTTPSRecord{}, false
	}
	target = normalizeHostname(target)
	parameters := make(map[string]string)
	for next < record.dataEnd {
		if next+4 > record.dataEnd {
			return HTTPSRecord{}, false
		}
		key := binary.BigEndian.Uint16(record.message[next : next+2])
		length := int(binary.BigEndian.Uint16(record.message[next+2 : next+4]))
		next += 4
		if next+length > record.dataEnd {
			return HTTPSRecord{}, false
		}
		value := record.message[next : next+length]
		next += length
		parameters[httpsParameterName(key)] = formatHTTPSParameter(key, value)
	}
	if target == "" {
		target = "."
	}
	return HTTPSRecord{
		Name:       record.name,
		TTL:        record.ttl,
		Priority:   priority,
		TargetName: target,
		Parameters: parameters,
	}, true
}

func httpsParameterName(key uint16) string {
	switch key {
	case 0:
		return "mandatory"
	case 1:
		return "alpn"
	case 2:
		return "no-default-alpn"
	case 3:
		return "port"
	case 4:
		return "ipv4hint"
	case 5:
		return "ech"
	case 6:
		return "ipv6hint"
	default:
		return fmt.Sprintf("key%d", key)
	}
}

func formatHTTPSParameter(key uint16, value []byte) string {
	switch key {
	case 0:
		var names []string
		for len(value) >= 2 {
			names = append(names, httpsParameterName(binary.BigEndian.Uint16(value[:2])))
			value = value[2:]
		}
		return strings.Join(names, ",")
	case 1:
		var protocols []string
		for len(value) > 0 {
			length := int(value[0])
			value = value[1:]
			if length > len(value) {
				return "invalid"
			}
			protocols = append(protocols, string(value[:length]))
			value = value[length:]
		}
		return strings.Join(protocols, ",")
	case 2:
		return "true"
	case 3:
		if len(value) == 2 {
			return strconv.Itoa(int(binary.BigEndian.Uint16(value)))
		}
	case 4:
		var addresses []string
		for len(value) >= net.IPv4len {
			addresses = append(addresses, net.IP(value[:net.IPv4len]).String())
			value = value[net.IPv4len:]
		}
		return strings.Join(addresses, ",")
	case 5:
		encoded := strings.ToUpper(hex.EncodeToString(value))
		if len(encoded) > 64 {
			return encoded[:64] + "..."
		}
		return encoded
	case 6:
		var addresses []string
		for len(value) >= net.IPv6len {
			addresses = append(addresses, net.IP(value[:net.IPv6len]).String())
			value = value[net.IPv6len:]
		}
		return strings.Join(addresses, ",")
	}
	return strings.ToUpper(hex.EncodeToString(value))
}

func inspectMailSecurity(host string) *MailSecurity {
	mail := &MailSecurity{}
	if records, err := net.LookupMX(host); err == nil {
		for _, record := range records {
			mail.MX = append(mail.MX, fmt.Sprintf("%d %s", record.Pref, normalizeHostname(record.Host)))
		}
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("MX lookup: %v", err))
	}
	if records, err := net.LookupTXT(host); err == nil {
		mail.SPF = filterTXT(records, "v=spf1")
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("SPF lookup: %v", err))
	}
	if records, err := net.LookupTXT("_dmarc." + host); err == nil {
		mail.DMARC = filterTXT(records, "v=dmarc1")
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("DMARC lookup: %v", err))
	}
	if records, err := net.LookupTXT("_mta-sts." + host); err == nil {
		mail.MTASTSRecord = filterTXT(records, "v=stsv1")
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("MTA-STS lookup: %v", err))
	}
	if records, err := net.LookupTXT("_smtp._tls." + host); err == nil {
		mail.TLSReporting = filterTXT(records, "v=tlsrptv1")
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("TLS-RPT lookup: %v", err))
	}
	return mail
}

func isDNSNotFound(err error) bool {
	var dnsError *net.DNSError
	return errors.As(err, &dnsError) && dnsError.IsNotFound
}

func filterTXT(records []string, prefix string) []string {
	var matches []string
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), prefix) {
			matches = append(matches, record)
		}
	}
	return matches
}

func printResult(result Result) {
	fmt.Printf("Hostname: %s\n", result.Hostname)
	if result.CNAME != "" {
		fmt.Printf("  Canonical name: %s\n", result.CNAME)
	}
	if len(result.ARecords) > 0 {
		fmt.Printf("  A records:      %s\n", strings.Join(result.ARecords, ", "))
	}
	if len(result.AAAARecords) > 0 {
		fmt.Printf("  AAAA records:   %s\n", strings.Join(result.AAAARecords, ", "))
	}
	if result.Error != "" && len(result.Endpoints) == 0 {
		fmt.Printf("  Error:          %s\n", result.Error)
	}
	if result.DNS.Resolver != "" {
		fmt.Printf("  DNS resolver:   %s\n", result.DNS.Resolver)
		fmt.Printf("  DNSSEC status:  %s\n", result.DNS.DNSSECStatus)
	}
	if result.DNS.Zone != "" {
		fmt.Printf("  DNS zone:       %s\n", result.DNS.Zone)
	}
	if len(result.DNS.CNAMEChain) > 0 {
		fmt.Printf("  CNAME chain:    %s\n", strings.Join(result.DNS.CNAMEChain, " -> "))
	}
	for _, record := range result.DNS.RecordTTLs {
		fmt.Printf("  DNS %-5s TTL:  %-6d %s -> %s\n", record.Type, record.TTL, record.Name, record.Value)
	}
	for _, record := range result.DNS.CAA {
		fmt.Printf("  CAA:            %s %d %s %q (TTL %d, dnssec=%v)\n",
			record.Name, record.Flags, record.Tag, record.Value, record.TTL, record.DNSSECValidated)
	}
	for _, record := range result.DNS.Nameservers {
		fmt.Printf("  Nameserver:     %s [%s] (TTL %d)\n",
			record.Name, valueOrDash(strings.Join(record.Addresses, ", ")), record.TTL)
	}
	for _, record := range result.DNS.TLSA {
		fmt.Printf("  TLSA:           usage=%d selector=%d match=%d certificate_match=%v dnssec=%v (TTL %d)\n",
			record.CertificateUsage, record.Selector, record.MatchingType,
			record.MatchesPresentedChain, record.DNSSECValidated, record.TTL)
	}
	for _, record := range result.DNS.HTTPS {
		fmt.Printf("  HTTPS record:   priority=%d target=%s params=%s (TTL %d, dnssec=%v)\n",
			record.Priority, valueOrDash(record.TargetName), formatStringMap(record.Parameters),
			record.TTL, record.DNSSECValidated)
	}
	for _, record := range result.DNS.DS {
		fmt.Printf("  DS:             key_tag=%d algorithm=%s digest_type=%d (TTL %d)\n",
			record.KeyTag, record.AlgorithmName, record.DigestType, record.TTL)
	}
	for _, record := range result.DNS.DNSKEY {
		fmt.Printf("  DNSKEY:         key_tag=%d flags=%d algorithm=%s (TTL %d)\n",
			record.KeyTag, record.Flags, record.AlgorithmName, record.TTL)
	}
	for _, record := range result.DNS.RRSIG {
		fmt.Printf("  RRSIG:          %s %s key_tag=%d valid=%s..%s\n",
			record.Name, record.TypeCovered, record.KeyTag,
			record.Inception.Format(time.RFC3339), record.Expiration.Format(time.RFC3339))
	}
	for _, err := range result.DNS.Errors {
		fmt.Printf("  DNS note:       %s\n", err)
	}

	for _, endpoint := range result.Endpoints {
		fmt.Printf("\n  Endpoint %s (%s, %s)\n", endpoint.IP, endpoint.AddressFamily, endpoint.IPClassification)
		fmt.Printf("    TCP reachable:       %v\n", endpoint.TCPReachable)
		fmt.Printf("    TLS handshake:       %v\n", endpoint.TLSHandshake)
		if endpoint.TLSHandshake {
			fmt.Printf("    Certificate valid:   %v\n", endpoint.CertificateValid)
			fmt.Printf("    Chain trusted:       %v\n", endpoint.ChainTrusted)
			fmt.Printf("    Hostname match:      %v\n", endpoint.HostnameMatch)
			fmt.Printf("    Negotiated TLS:      %s\n", endpoint.TLSVersion)
			fmt.Printf("    Supported TLS:       %s\n", valueOrDash(strings.Join(endpoint.SupportedTLSVersions, ", ")))
			fmt.Printf("    Cipher suite:        %s\n", valueOrDash(endpoint.CipherSuite))
			fmt.Printf("    Key exchange:        %s\n", valueOrDash(endpoint.KeyExchange))
			fmt.Printf("    ALPN:                %s\n", valueOrDash(endpoint.ALPN))
			fmt.Printf("    OCSP staple:         %v\n", endpoint.OCSPStapled)
			fmt.Printf("    SCTs:                %d\n", endpoint.SCTCount)
		}
		if endpoint.Certificate != nil {
			cert := endpoint.Certificate
			fmt.Printf("    Subject:             %s\n", cert.Subject)
			fmt.Printf("    SANs:                %s\n", valueOrDash(strings.Join(cert.AltNames, ", ")))
			fmt.Printf("    Issuer:              %s\n", cert.Issuer)
			fmt.Printf("    Validity:            %s to %s (%d days remaining; %s)\n",
				cert.Issued.Format(time.RFC3339), cert.Expiry.Format(time.RFC3339),
				cert.DaysRemaining, cert.TimeStatus)
			fmt.Printf("    Public key:          %s\n", publicKeyDescription(*cert))
			fmt.Printf("    Signature algorithm: %s\n", cert.SignatureAlgorithm)
			fmt.Printf("    Serial number:       %s\n", cert.SerialNumber)
			fmt.Printf("    SHA-256 fingerprint: %s\n", cert.FingerprintSHA256)
			fmt.Printf("    Served chain length: %d\n", len(endpoint.PeerChain))
			if len(endpoint.VerifiedChain) > 0 {
				fmt.Printf("    Verified chain:      %s\n", chainSummary(endpoint.VerifiedChain))
			}
		}
		if endpoint.VerificationError != "" {
			fmt.Printf("    Verification error:  %s\n", endpoint.VerificationError)
		}
		if endpoint.Error != "" {
			fmt.Printf("    Error:               %s\n", endpoint.Error)
		}
		if len(endpoint.SupportedCipherSuites) > 0 {
			for _, version := range sortedMapKeys(endpoint.SupportedCipherSuites) {
				fmt.Printf("    %s ciphers:      %s\n", version, strings.Join(endpoint.SupportedCipherSuites[version], ", "))
			}
		}
	}

	if result.Mail != nil {
		fmt.Println("\n  Mail security")
		fmt.Printf("    MX:          %s\n", valueOrDash(strings.Join(result.Mail.MX, ", ")))
		fmt.Printf("    SPF:         %s\n", valueOrDash(strings.Join(result.Mail.SPF, " | ")))
		fmt.Printf("    DMARC:       %s\n", valueOrDash(strings.Join(result.Mail.DMARC, " | ")))
		fmt.Printf("    MTA-STS DNS: %s\n", valueOrDash(strings.Join(result.Mail.MTASTSRecord, " | ")))
		fmt.Printf("    TLS-RPT:     %s\n", valueOrDash(strings.Join(result.Mail.TLSReporting, " | ")))
		for _, err := range result.Mail.Errors {
			fmt.Printf("    Note:        %s\n", err)
		}
	}

	if result.HTTP != nil {
		fmt.Println("\n  HTTP security")
		cleartext := result.HTTP.CleartextProbe
		fmt.Printf("    Cleartext probe: %s -> %s (status %d)\n",
			cleartext.RequestedURL, valueOrDash(cleartext.FinalURL), cleartext.StatusCode)
		for _, page := range result.HTTP.Pages {
			fmt.Printf("    HTTPS page:     %s -> %s (status %d, %s, remote %s, bytes %d, truncated=%v)\n",
				page.RequestedURL, valueOrDash(page.FinalURL), page.StatusCode,
				valueOrDash(page.HTTPProtocol), valueOrDash(page.RemoteIP), page.BytesRead, page.BodyTruncated)
		}
		securityTXT := result.HTTP.SecurityTXT
		fmt.Printf("    security.txt:   %s (present=%v, status=%d, contacts=%d)\n",
			securityTXT.RequestedURL, securityTXT.Present, securityTXT.StatusCode, len(securityTXT.Contacts))
		for _, err := range result.HTTP.Errors {
			fmt.Printf("    HTTP note:      %s\n", err)
		}
	}

	if len(result.Findings) > 0 {
		fmt.Println("\n  Findings")
		for _, item := range result.Findings {
			fmt.Printf("    [%s] %s: %s\n", strings.ToUpper(item.Severity), item.Code, item.Message)
		}
	}
	fmt.Println()
}

func printMarkdown(results []Result) {
	fmt.Println("| Hostname | IP | Family | Certificate valid | Negotiated TLS | Supported TLS | Cipher | Key exchange | ALPN | Expiry | Days | DNSSEC | CAA | Findings | Error |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |")
	for _, result := range results {
		if len(result.Endpoints) == 0 {
			fmt.Printf("| %s |  |  | false |  |  |  |  |  |  |  | %s | %s | %s | %s |\n",
				markdownCell(result.Hostname), markdownCell(result.DNS.DNSSECStatus),
				markdownCell(caaSummary(result.DNS.CAA)), markdownCell(findingCodes(result.Findings)),
				markdownCell(result.Error))
			continue
		}
		for _, endpoint := range result.Endpoints {
			expiry := ""
			days := ""
			if endpoint.Certificate != nil {
				expiry = endpoint.Certificate.Expiry.Format(time.RFC3339)
				days = strconv.Itoa(endpoint.Certificate.DaysRemaining)
			}
			fmt.Printf("| %s | %s | %s | %v | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				markdownCell(result.Hostname),
				markdownCell(endpoint.IP),
				markdownCell(endpoint.AddressFamily),
				endpoint.CertificateValid,
				markdownCell(endpoint.TLSVersion),
				markdownCell(strings.Join(endpoint.SupportedTLSVersions, ", ")),
				markdownCell(endpoint.CipherSuite),
				markdownCell(endpoint.KeyExchange),
				markdownCell(endpoint.ALPN),
				markdownCell(expiry),
				days,
				markdownCell(result.DNS.DNSSECStatus),
				markdownCell(caaSummary(result.DNS.CAA)),
				markdownCell(findingCodes(append(result.Findings, endpoint.Findings...))),
				markdownCell(firstNonEmpty(endpoint.Error, endpoint.VerificationError)),
			)
		}
	}
}

func finding(code, severity, message string) Finding {
	return Finding{Code: code, Severity: severity, Message: message}
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

func certificateTimeStatus(cert *x509.Certificate, now time.Time) string {
	if now.Before(cert.NotBefore) {
		return "not_yet_valid"
	}
	if now.After(cert.NotAfter) {
		return "expired"
	}
	return "valid"
}

func daysRemaining(now, expiry time.Time) int {
	duration := expiry.Sub(now)
	if duration >= 0 {
		return int((duration + 24*time.Hour - 1) / (24 * time.Hour))
	}
	return -int((-duration + 24*time.Hour - 1) / (24 * time.Hour))
}

func colonHex(data []byte) string {
	encoded := strings.ToUpper(hex.EncodeToString(data))
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return strings.Join(parts, ":")
}

func keyUsageStrings(usage x509.KeyUsage) []string {
	values := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "certificate_signing"},
		{x509.KeyUsageCRLSign, "crl_signing"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	var result []string
	for _, value := range values {
		if usage&value.flag != 0 {
			result = append(result, value.name)
		}
	}
	return result
}

func extendedKeyUsageStrings(usages []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "any",
		x509.ExtKeyUsageServerAuth:                     "server_auth",
		x509.ExtKeyUsageClientAuth:                     "client_auth",
		x509.ExtKeyUsageCodeSigning:                    "code_signing",
		x509.ExtKeyUsageEmailProtection:                "email_protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "ipsec_end_system",
		x509.ExtKeyUsageIPSECTunnel:                    "ipsec_tunnel",
		x509.ExtKeyUsageIPSECUser:                      "ipsec_user",
		x509.ExtKeyUsageTimeStamping:                   "time_stamping",
		x509.ExtKeyUsageOCSPSigning:                    "ocsp_signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoft_server_gated_crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscape_server_gated_crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoft_commercial_code_signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoft_kernel_code_signing",
	}
	result := make([]string, 0, len(usages))
	for _, usage := range usages {
		if name, ok := names[usage]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("unknown_%d", usage))
		}
	}
	return result
}

func addressFamily(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func classifyIP(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "invalid"
	}
	if address.IsLoopback() {
		return "loopback"
	}
	if address.IsPrivate() {
		return "private"
	}
	if address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return "link-local"
	}
	if address.IsUnspecified() {
		return "unspecified"
	}
	if address.IsMulticast() {
		return "multicast"
	}
	prefixes := []struct {
		prefix netip.Prefix
		name   string
	}{
		{netip.MustParsePrefix("100.64.0.0/10"), "shared"},
		{netip.MustParsePrefix("192.0.2.0/24"), "documentation"},
		{netip.MustParsePrefix("198.51.100.0/24"), "documentation"},
		{netip.MustParsePrefix("203.0.113.0/24"), "documentation"},
		{netip.MustParsePrefix("2001:db8::/32"), "documentation"},
	}
	for _, item := range prefixes {
		if item.prefix.Contains(address) {
			return item.name
		}
	}
	if !address.IsGlobalUnicast() {
		return "reserved"
	}
	return "public"
}

func publicKeyDescription(cert CertificateInfo) string {
	parts := []string{cert.PublicKeyAlgorithm}
	if cert.PublicKeyBits > 0 {
		parts = append(parts, strconv.Itoa(cert.PublicKeyBits)+" bits")
	}
	if cert.PublicKeyCurve != "" {
		parts = append(parts, cert.PublicKeyCurve)
	}
	return strings.Join(parts, ", ")
}

func chainSummary(chain []CertificateInfo) string {
	names := make([]string, 0, len(chain))
	for _, cert := range chain {
		name := cert.Subject
		if name == "" {
			name = cert.FingerprintSHA256
		}
		names = append(names, name)
	}
	return strings.Join(names, " -> ")
}

func findingCodes(findings []Finding) string {
	seen := make(map[string]bool)
	var codes []string
	for _, item := range findings {
		if !seen[item.Code] {
			seen[item.Code] = true
			codes = append(codes, item.Code)
		}
	}
	sort.Strings(codes)
	return strings.Join(codes, ", ")
}

func sortedMapKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func formatStringMap(values map[string]string) string {
	if len(values) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, ", ")
}

func caaSummary(records []CAARecord) string {
	parts := make([]string, 0, len(records))
	for _, record := range records {
		parts = append(parts, record.Tag+"="+record.Value)
	}
	return strings.Join(parts, ", ")
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", "<br>")
	return value
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
