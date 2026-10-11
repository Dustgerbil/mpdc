package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

func (scanner *hostScanner) inspectMailSecurity(ctx context.Context, host string) *MailSecurity {
	mail := &MailSecurity{}
	if records, err := scanner.resolver.LookupMX(ctx, host); err == nil {
		for _, record := range records {
			mail.MX = append(mail.MX, fmt.Sprintf("%d %s", record.Pref, normalizeHostname(record.Host)))
		}
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("MX lookup: %v", err))
	}
	if records, err := scanner.resolver.LookupTXT(ctx, host); err == nil {
		mail.SPF = filterTXT(records, "v=spf1")
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("SPF lookup: %v", err))
	}
	if records, err := scanner.resolver.LookupTXT(ctx, "_dmarc."+host); err == nil {
		mail.DMARC = filterTXT(records, "v=dmarc1")
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("DMARC lookup: %v", err))
	}
	if records, err := scanner.resolver.LookupTXT(ctx, "_mta-sts."+host); err == nil {
		mail.MTASTSRecord = filterTXT(records, "v=stsv1")
	} else if !isDNSNotFound(err) {
		mail.Errors = append(mail.Errors, fmt.Sprintf("MTA-STS lookup: %v", err))
	}
	if records, err := scanner.resolver.LookupTXT(ctx, "_smtp._tls."+host); err == nil {
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
