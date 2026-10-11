package main

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

func addEndpointFindings(endpoint *EndpointResult) {
	if endpoint.Incomplete && !endpoint.TLSHandshake {
		return
	}
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
		if !endpoint.Incomplete {
			key := strings.Join(endpoint.SupportedTLSVersions, ",")
			versionSets[key] = append(versionSets[key], endpoint.IP)
		}
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

func addDNSFindings(result *Result) {
	if result.DNS.DNSSECStatus == "not_validated" {
		result.Findings = append(result.Findings, finding(
			"DNSSEC_NOT_VALIDATED", "info",
			"The selected resolver did not authenticate the address response with DNSSEC. This does not distinguish an unsigned zone from a non-validating resolver."))
	}
	addTLSAFindings(result)

	if result.DNS.Zone != "" && result.DNS.NameserverStatus == "available" && len(result.DNS.Nameservers) < 2 {
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

func finding(code, severity, message string) Finding {
	return Finding{Code: code, Severity: severity, Message: message}
}
