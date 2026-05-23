package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type Result struct {
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
}

func main() {
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	markdownOutput := flag.Bool("markdown", false, "Output in Markdown format")
	hostFile := flag.String("file", "", "Read hostnames from a text file (one per line)")
	flag.Parse()

	if *jsonOutput && *markdownOutput {
		fmt.Fprintln(os.Stderr, "Error: --json and --markdown flags are mutually exclusive.")
		os.Exit(1)
	}

	hostnames := flag.Args()

	// Check if stdin has data
	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				// Split line into words in case multiple hostnames are on one line
				words := strings.Fields(line)
				hostnames = append(hostnames, words...)
			}
		}
	}

	// Read hostnames from file if specified
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
				words := strings.Fields(line)
				hostnames = append(hostnames, words...)
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

	results := make([]Result, 0, len(hostnames))
	for _, host := range hostnames {
		results = append(results, inspectHost(host))
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
		for _, r := range results {
			printResult(r)
		}
	}
}

func inspectHost(host string) Result {
	res := Result{Hostname: host}

	// 1. Resolve CNAME and IP addresses
	cname, err := net.LookupCNAME(host)
	if err == nil {
		// LookupCNAME returns the host itself if it's not a CNAME, or the target if it is.
		// We normalize by only setting it if it differs from the original host.
		normalizedHost := strings.TrimSuffix(host, ".")
		normalizedCNAME := strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(normalizedCNAME, normalizedHost) {
			res.CNAME = normalizedCNAME
		}
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		res.Error = fmt.Sprintf("DNS lookup failed: %v", err)
		return res
	}
	for _, ip := range ips {
		res.IPs = append(res.IPs, ip.String())
	}

	// 2. Check HTTPS and get certificate details
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	// Note: tls.Dial will negotiate the highest mutually supported version.
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", nil)
	if err != nil {
		res.Reachable = false
		res.Error = fmt.Sprintf("HTTPS connection failed: %v", err)
		return res
	}
	defer conn.Close()

	res.Reachable = true
	state := conn.ConnectionState()
	res.TLSVersion = tlsVersionToString(state.Version)

	certs := state.PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		res.Subject = cert.Subject.String()
		res.Issuer = cert.Issuer.String()
		res.Issued = cert.NotBefore
		res.Expiry = cert.NotAfter
		res.AltNames = cert.DNSNames
	}

	return res
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%x)", v)
	}
}

func printResult(r Result) {
	fmt.Printf("Hostname: %s\n", r.Hostname)
	if r.CNAME != "" {
		fmt.Printf("  CNAME:    %s\n", r.CNAME)
	}
	if len(r.IPs) > 0 {
		fmt.Printf("  IPs:      %s\n", strings.Join(r.IPs, ", "))
	}
	if r.Error != "" {
		fmt.Printf("  Error:    %s\n", r.Error)
	} else {
		fmt.Printf("  Reachable: %v\n", r.Reachable)
		fmt.Printf("  TLS Ver:   %s\n", r.TLSVersion)
		fmt.Printf("  Subject:   %s\n", r.Subject)
		if len(r.AltNames) > 0 {
			fmt.Printf("  Alt Names: %s\n", strings.Join(r.AltNames, ", "))
		}
		fmt.Printf("  Issuer:    %s\n", r.Issuer)
		fmt.Printf("  Issued:    %s\n", r.Issued.Format(time.RFC3339))
		fmt.Printf("  Expiry:    %s\n", r.Expiry.Format(time.RFC3339))
	}
	fmt.Println()
}

func printMarkdown(results []Result) {
	fmt.Println("| Hostname | CNAME | IPs | Reachable | TLS Ver | Subject | Alt Names | Issuer | Issued | Expiry | Error |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, r := range results {
		ips := strings.Join(r.IPs, ", ")
		altNames := strings.Join(r.AltNames, ", ")
		issued := ""
		if !r.Issued.IsZero() {
			issued = r.Issued.Format(time.RFC3339)
		}
		expiry := ""
		if !r.Expiry.IsZero() {
			expiry = r.Expiry.Format(time.RFC3339)
		}
		fmt.Printf("| %s | %s | %s | %v | %s | %s | %s | %s | %s | %s | %s |\n",
			r.Hostname, r.CNAME, ips, r.Reachable, r.TLSVersion, r.Subject, altNames, r.Issuer, issued, expiry, r.Error)
	}
}
