package main

import (
	"encoding/hex"
	"fmt"
)

// The record-level matches_presented_chain field remains an any-endpoint
// observation for schema compatibility. Findings and status are per endpoint.
func addTLSAFindings(result *Result) {
	if len(result.DNS.TLSA) == 0 {
		return
	}
	var usable []TLSARecord
	validated := false
	for _, record := range result.DNS.TLSA {
		if !record.DNSSECValidated {
			continue
		}
		validated = true
		if usableTLSARecord(record) {
			usable = append(usable, record)
		}
	}
	if !validated {
		result.Findings = append(result.Findings, finding("DANE_TLSA_NOT_VALIDATED", "info", "TLSA records were found but were not authenticated by the selected resolver."))
		return
	}
	if len(usable) == 0 {
		result.Findings = append(result.Findings, finding("DANE_TLSA_UNAVAILABLE", "info", "No supported, well-formed DNSSEC-validated TLSA records were available for certificate comparison."))
		for i := range result.Endpoints {
			result.Endpoints[i].TLSAStatus = "unavailable"
		}
		return
	}
	if len(result.Endpoints) == 0 {
		result.Findings = append(result.Findings, finding("DANE_TLSA_UNAVAILABLE", "info", "DNSSEC-validated TLSA records were found, but no endpoint certificates were available for comparison."))
	}
	for i := range result.Endpoints {
		endpoint := &result.Endpoints[i]
		var item Finding
		if len(endpoint.peerCertificates) == 0 {
			endpoint.TLSAStatus = "unavailable"
			item = finding("DANE_TLSA_UNAVAILABLE", "info", fmt.Sprintf("%s presented no certificate for comparison with DNSSEC-validated TLSA records.", endpoint.IP))
		} else {
			endpoint.TLSAStatus = "mismatched"
			for _, record := range usable {
				if tlsaMatchesEndpoints(record, []EndpointResult{*endpoint}) {
					endpoint.TLSAStatus = "matched"
					break
				}
			}
			if endpoint.TLSAStatus == "matched" {
				continue
			}
			item = finding("DANE_TLSA_MISMATCH", "critical", fmt.Sprintf("DNSSEC-validated TLSA records do not match the presented certificate chain on %s.", endpoint.IP))
		}
		endpoint.Findings = append(endpoint.Findings, item)
		result.Findings = append(result.Findings, item)
	}
}

func usableTLSARecord(record TLSARecord) bool {
	if record.CertificateUsage > 3 || record.Selector > 1 || record.MatchingType > 2 {
		return false
	}
	association, err := hex.DecodeString(record.AssociationData)
	if err != nil || len(association) == 0 {
		return false
	}
	switch record.MatchingType {
	case 1:
		return len(association) == 32
	case 2:
		return len(association) == 64
	default:
		return true
	}
}
