package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

func (scanner *hostScanner) inspectAdvancedDNS(ctx context.Context, host, configuredResolver string, endpoints []EndpointResult) DNSDetails {
	details := DNSDetails{DNSSECStatus: "unavailable", NameserverStatus: "unavailable"}
	resolver, err := dnsResolverAddress(configuredResolver)
	if err != nil {
		details.Errors = append(details.Errors, err.Error())
		return details
	}
	details.Resolver = resolver

	aResponse, aErr := scanner.query(ctx, resolver, host, dnsTypeA)
	aaaaResponse, aaaaErr := scanner.query(ctx, resolver, host, dnsTypeAAAA)
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

	caa, caaErr := scanner.lookupRelevantCAA(ctx, resolver, host)
	if caaErr != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("CAA query: %v", caaErr))
	} else {
		details.CAA = caa
	}

	tlsaName := "_443._tcp." + host
	tlsaResponse, tlsaErr := scanner.query(ctx, resolver, tlsaName, dnsTypeTLSA)
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

	httpsResponse, httpsErr := scanner.query(ctx, resolver, host, dnsTypeHTTPS)
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
	scanner.inspectDNSSECZone(ctx, resolver, host, &details)
	return details
}

func (scanner *hostScanner) inspectDNSSECZone(ctx context.Context, resolver, host string, details *DNSDetails) {
	soaResponse, err := scanner.query(ctx, resolver, host, dnsTypeSOA)
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

	nsResponse, err := scanner.query(ctx, resolver, zone, dnsTypeNS)
	if err != nil {
		details.Errors = append(details.Errors, fmt.Sprintf("NS query: %v", err))
	} else {
		details.NameserverStatus = "available"
		for _, record := range nsResponse.answers {
			if record.recordType != dnsTypeNS {
				continue
			}
			target, _, nameErr := readDNSName(record.message, record.dataOffset)
			if nameErr != nil {
				details.NameserverStatus = "unavailable"
				details.Errors = append(details.Errors, fmt.Sprintf("NS record: %v", nameErr))
				continue
			}
			entry := NameserverRecord{Name: normalizeHostname(target), TTL: record.ttl}
			if addresses, lookupErr := scanner.resolver.LookupHost(ctx, entry.Name); lookupErr == nil {
				entry.Addresses = append(entry.Addresses, addresses...)
				sort.Strings(entry.Addresses)
			}
			details.Nameservers = append(details.Nameservers, entry)
		}
	}

	dsResponse, err := scanner.query(ctx, resolver, zone, dnsTypeDS)
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

	keyResponse, err := scanner.query(ctx, resolver, zone, dnsTypeDNSKEY)
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

func (scanner *hostScanner) lookupRelevantCAA(ctx context.Context, resolver, host string) ([]CAARecord, error) {
	labels := strings.Split(normalizeHostname(host), ".")
	for i := 0; i < len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		response, err := scanner.query(ctx, resolver, name, dnsTypeCAA)
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
