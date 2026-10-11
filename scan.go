package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
)

func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.TrimSpace(host), ".")
}

type hostResolver interface {
	LookupCNAME(context.Context, string) (string, error)
	LookupIP(context.Context, string, string) ([]net.IP, error)
	LookupHost(context.Context, string) ([]string, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupTXT(context.Context, string) ([]string, error)
}

type hostScanner struct {
	resolver hostResolver
	query    func(context.Context, string, string, uint16) (dnsWireResponse, error)
	connect  func(context.Context, string, string, *tls.Config) (tls.ConnectionState, bool, error)
	newHTTP  func(HTTPScanOptions) *httpScanner
}

func newHostScanner() *hostScanner {
	return &hostScanner{resolver: timeoutResolver{net.DefaultResolver}, query: dnsQuery, connect: connectTLS, newHTTP: newHTTPScanner}
}

func (scanner *hostScanner) inspectHost(ctx context.Context, host string, opts options) (result Result) {
	result = Result{SchemaVersion: jsonSchemaVersion, Hostname: host, DNS: DNSDetails{DNSSECStatus: "unavailable"}}
	defer func() {
		if err := ctx.Err(); err != nil {
			result.Incomplete = true
			result.Error = joinErrors(result.Error, "scan incomplete: "+err.Error())
			result.Findings = append(result.Findings, finding("SCAN_INCOMPLETE", "info", "The scan budget expired or the scan was canceled; some checks were not completed."))
		}
	}()
	if ctx.Err() != nil {
		return result
	}
	if host == "" {
		result.Error = "empty hostname"
		result.Findings = append(result.Findings, finding("INPUT_INVALID", "critical", "The hostname is empty."))
		return result
	}

	cname, err := scanner.resolver.LookupCNAME(ctx, host)
	if err == nil {
		cname = normalizeHostname(cname)
		if !strings.EqualFold(cname, host) {
			result.CNAME = cname
		}
	}

	ips, err := scanner.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		result.Error = fmt.Sprintf("DNS lookup failed: %v", err)
		if ctx.Err() != nil {
			return result
		}
		result.Findings = append(result.Findings, finding("DNS_LOOKUP_FAILED", "critical", result.Error))
		result.DNS = scanner.inspectAdvancedDNS(ctx, host, opts.dnsServer, nil)
		addDNSFindings(&result)
		if len(result.DNS.CNAMEChain) > 0 && len(result.DNS.RecordTTLs) == len(result.DNS.CNAMEChain) {
			result.Findings = append(result.Findings, finding(
				"POSSIBLE_DANGLING_CNAME", "warning",
				"The CNAME chain did not produce an address. This is a risk indicator, not proof that the target is claimable."))
		}
		if opts.mail {
			result.Mail = scanner.inspectMailSecurity(ctx, host)
		}
		scanner.addHTTPInspection(ctx, &result, opts.http)
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

	result.Endpoints = scanner.inspectEndpoints(ctx, host, result.IPs, opts.scanCiphers, opts.concurrency)
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
	result.DNS = scanner.inspectAdvancedDNS(ctx, host, opts.dnsServer, result.Endpoints)
	addDNSFindings(&result)
	populateCompatibilityFields(&result)

	if opts.mail {
		result.Mail = scanner.inspectMailSecurity(ctx, host)
	}
	scanner.addHTTPInspection(ctx, &result, opts.http)
	return result
}
