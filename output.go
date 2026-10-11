package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

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

func printResult(w io.Writer, result Result) {
	fmt.Fprintf(w, "Hostname: %s\n", result.Hostname)
	if result.CNAME != "" {
		fmt.Fprintf(w, "  Canonical name: %s\n", result.CNAME)
	}
	if len(result.ARecords) > 0 {
		fmt.Fprintf(w, "  A records:      %s\n", strings.Join(result.ARecords, ", "))
	}
	if len(result.AAAARecords) > 0 {
		fmt.Fprintf(w, "  AAAA records:   %s\n", strings.Join(result.AAAARecords, ", "))
	}
	if result.Error != "" && (result.Incomplete || len(result.Endpoints) == 0) {
		fmt.Fprintf(w, "  Error:          %s\n", result.Error)
	}
	if result.DNS.Resolver != "" {
		fmt.Fprintf(w, "  DNS resolver:   %s\n", result.DNS.Resolver)
		fmt.Fprintf(w, "  DNSSEC status:  %s\n", result.DNS.DNSSECStatus)
	}
	if result.DNS.Zone != "" {
		fmt.Fprintf(w, "  DNS zone:       %s\n", result.DNS.Zone)
	}
	if len(result.DNS.CNAMEChain) > 0 {
		fmt.Fprintf(w, "  CNAME chain:    %s\n", strings.Join(result.DNS.CNAMEChain, " -> "))
	}
	for _, record := range result.DNS.RecordTTLs {
		fmt.Fprintf(w, "  DNS %-5s TTL:  %-6d %s -> %s\n", record.Type, record.TTL, record.Name, record.Value)
	}
	for _, record := range result.DNS.CAA {
		fmt.Fprintf(w, "  CAA:            %s %d %s %q (TTL %d, dnssec=%v)\n",
			record.Name, record.Flags, record.Tag, record.Value, record.TTL, record.DNSSECValidated)
	}
	for _, record := range result.DNS.Nameservers {
		fmt.Fprintf(w, "  Nameserver:     %s [%s] (TTL %d)\n",
			record.Name, valueOrDash(strings.Join(record.Addresses, ", ")), record.TTL)
	}
	for _, record := range result.DNS.TLSA {
		fmt.Fprintf(w, "  TLSA:           usage=%d selector=%d match=%d certificate_match=%v dnssec=%v (TTL %d)\n",
			record.CertificateUsage, record.Selector, record.MatchingType,
			record.MatchesPresentedChain, record.DNSSECValidated, record.TTL)
	}
	for _, record := range result.DNS.HTTPS {
		fmt.Fprintf(w, "  HTTPS record:   priority=%d target=%s params=%s (TTL %d, dnssec=%v)\n",
			record.Priority, valueOrDash(record.TargetName), formatStringMap(record.Parameters),
			record.TTL, record.DNSSECValidated)
	}
	for _, record := range result.DNS.DS {
		fmt.Fprintf(w, "  DS:             key_tag=%d algorithm=%s digest_type=%d (TTL %d)\n",
			record.KeyTag, record.AlgorithmName, record.DigestType, record.TTL)
	}
	for _, record := range result.DNS.DNSKEY {
		fmt.Fprintf(w, "  DNSKEY:         key_tag=%d flags=%d algorithm=%s (TTL %d)\n",
			record.KeyTag, record.Flags, record.AlgorithmName, record.TTL)
	}
	for _, record := range result.DNS.RRSIG {
		fmt.Fprintf(w, "  RRSIG:          %s %s key_tag=%d valid=%s..%s\n",
			record.Name, record.TypeCovered, record.KeyTag,
			record.Inception.Format(time.RFC3339), record.Expiration.Format(time.RFC3339))
	}
	for _, err := range result.DNS.Errors {
		fmt.Fprintf(w, "  DNS note:       %s\n", err)
	}

	for _, endpoint := range result.Endpoints {
		fmt.Fprintf(w, "\n  Endpoint %s (%s, %s)\n", endpoint.IP, endpoint.AddressFamily, endpoint.IPClassification)
		fmt.Fprintf(w, "    TCP reachable:       %v\n", endpoint.TCPReachable)
		fmt.Fprintf(w, "    TLS handshake:       %v\n", endpoint.TLSHandshake)
		if endpoint.TLSAStatus != "" {
			fmt.Fprintf(w, "    TLSA comparison:     %s\n", endpoint.TLSAStatus)
		}
		if endpoint.TLSHandshake {
			fmt.Fprintf(w, "    Certificate valid:   %v\n", endpoint.CertificateValid)
			fmt.Fprintf(w, "    Chain trusted:       %v\n", endpoint.ChainTrusted)
			fmt.Fprintf(w, "    Hostname match:      %v\n", endpoint.HostnameMatch)
			fmt.Fprintf(w, "    Negotiated TLS:      %s\n", endpoint.TLSVersion)
			fmt.Fprintf(w, "    Supported TLS:       %s\n", valueOrDash(strings.Join(endpoint.SupportedTLSVersions, ", ")))
			fmt.Fprintf(w, "    Cipher suite:        %s\n", valueOrDash(endpoint.CipherSuite))
			fmt.Fprintf(w, "    Key exchange:        %s\n", valueOrDash(endpoint.KeyExchange))
			fmt.Fprintf(w, "    ALPN:                %s\n", valueOrDash(endpoint.ALPN))
			fmt.Fprintf(w, "    OCSP staple:         %v\n", endpoint.OCSPStapled)
			fmt.Fprintf(w, "    SCTs:                %d\n", endpoint.SCTCount)
		}
		if endpoint.Certificate != nil {
			cert := endpoint.Certificate
			fmt.Fprintf(w, "    Subject:             %s\n", cert.Subject)
			fmt.Fprintf(w, "    SANs:                %s\n", valueOrDash(strings.Join(cert.AltNames, ", ")))
			fmt.Fprintf(w, "    Issuer:              %s\n", cert.Issuer)
			fmt.Fprintf(w, "    Validity:            %s to %s (%d days remaining; %s)\n",
				cert.Issued.Format(time.RFC3339), cert.Expiry.Format(time.RFC3339),
				cert.DaysRemaining, cert.TimeStatus)
			fmt.Fprintf(w, "    Public key:          %s\n", publicKeyDescription(*cert))
			fmt.Fprintf(w, "    Signature algorithm: %s\n", cert.SignatureAlgorithm)
			fmt.Fprintf(w, "    Serial number:       %s\n", cert.SerialNumber)
			fmt.Fprintf(w, "    SHA-256 fingerprint: %s\n", cert.FingerprintSHA256)
			fmt.Fprintf(w, "    Served chain length: %d\n", len(endpoint.PeerChain))
			if len(endpoint.VerifiedChain) > 0 {
				fmt.Fprintf(w, "    Verified chain:      %s\n", chainSummary(endpoint.VerifiedChain))
			}
		}
		if endpoint.VerificationError != "" {
			fmt.Fprintf(w, "    Verification error:  %s\n", endpoint.VerificationError)
		}
		if endpoint.Error != "" {
			fmt.Fprintf(w, "    Error:               %s\n", endpoint.Error)
		}
		if len(endpoint.SupportedCipherSuites) > 0 {
			for _, version := range sortedMapKeys(endpoint.SupportedCipherSuites) {
				fmt.Fprintf(w, "    %s ciphers:      %s\n", version, strings.Join(endpoint.SupportedCipherSuites[version], ", "))
			}
		}
	}

	if result.Mail != nil {
		fmt.Fprintln(w, "\n  Mail security")
		fmt.Fprintf(w, "    MX:          %s\n", valueOrDash(strings.Join(result.Mail.MX, ", ")))
		fmt.Fprintf(w, "    SPF:         %s\n", valueOrDash(strings.Join(result.Mail.SPF, " | ")))
		fmt.Fprintf(w, "    DMARC:       %s\n", valueOrDash(strings.Join(result.Mail.DMARC, " | ")))
		fmt.Fprintf(w, "    MTA-STS DNS: %s\n", valueOrDash(strings.Join(result.Mail.MTASTSRecord, " | ")))
		fmt.Fprintf(w, "    TLS-RPT:     %s\n", valueOrDash(strings.Join(result.Mail.TLSReporting, " | ")))
		for _, err := range result.Mail.Errors {
			fmt.Fprintf(w, "    Note:        %s\n", err)
		}
	}

	if result.HTTP != nil {
		fmt.Fprintln(w, "\n  HTTP security")
		cleartext := result.HTTP.CleartextProbe
		fmt.Fprintf(w, "    Cleartext probe: %s -> %s (status %d)\n",
			cleartext.RequestedURL, valueOrDash(cleartext.FinalURL), cleartext.StatusCode)
		for _, page := range result.HTTP.Pages {
			fmt.Fprintf(w, "    HTTPS page:     %s -> %s (status %d, %s, remote %s, bytes %d, truncated=%v)\n",
				page.RequestedURL, valueOrDash(page.FinalURL), page.StatusCode,
				valueOrDash(page.HTTPProtocol), valueOrDash(page.RemoteIP), page.BytesRead, page.BodyTruncated)
		}
		securityTXT := result.HTTP.SecurityTXT
		fmt.Fprintf(w, "    security.txt:   %s (present=%v, status=%d, contacts=%d)\n",
			securityTXT.RequestedURL, securityTXT.Present, securityTXT.StatusCode, len(securityTXT.Contacts))
		for _, err := range result.HTTP.Errors {
			fmt.Fprintf(w, "    HTTP note:      %s\n", err)
		}
	}

	if len(result.Findings) > 0 {
		fmt.Fprintln(w, "\n  Findings")
		for _, item := range result.Findings {
			fmt.Fprintf(w, "    [%s] %s: %s\n", strings.ToUpper(item.Severity), item.Code, item.Message)
		}
	}
	fmt.Fprintln(w)
}

func printMarkdown(w io.Writer, results []Result) {
	fmt.Fprintln(w, "| Hostname | IP | Family | Certificate valid | Negotiated TLS | Supported TLS | Cipher | Key exchange | ALPN | Expiry | Days | DNSSEC | CAA | Findings | Error |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |")
	for _, result := range results {
		if len(result.Endpoints) == 0 {
			fmt.Fprintf(w, "| %s |  |  | false |  |  |  |  |  |  |  | %s | %s | %s | %s |\n",
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
			fmt.Fprintf(w, "| %s | %s | %s | %v | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
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
				markdownCell(firstNonEmpty(endpoint.Error, endpoint.VerificationError, result.Error)),
			)
		}
	}
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
