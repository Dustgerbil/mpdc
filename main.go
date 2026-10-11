package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	connectionTimeout  = 5 * time.Second
	jsonSchemaVersion  = 2
	defaultScanTimeout = 5 * time.Minute
	defaultConcurrency = 8
	maxConcurrency     = 64
)

var version = "0.2.0"

type options struct {
	concurrency int
	scanCiphers bool
	mail        bool
	dnsServer   string
	http        HTTPScanOptions
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var input io.Reader
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		input = os.Stdin
	}
	code := run(ctx, os.Args[1:], input, os.Stdout, os.Stderr, newHostScanner())
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, input io.Reader, output, errorOutput io.Writer, inspector *hostScanner) int {
	flags := flag.NewFlagSet("mpdc", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	scanTimeout := flags.Duration("scan-timeout", defaultScanTimeout, "Overall network scan budget for all hostnames")
	concurrency := flags.Int("concurrency", defaultConcurrency, "Maximum simultaneous endpoint inspections (1-64)")
	jsonOutput := flags.Bool("json", false, "Output in JSON format")
	markdownOutput := flags.Bool("markdown", false, "Output in Markdown format")
	hostFile := flags.String("file", "", "Read hostnames from a text file (one per line)")
	scanCiphers := flags.Bool("scan-ciphers", false, "Actively enumerate accepted TLS 1.0-1.2 cipher suites (slow)")
	mail := flags.Bool("mail", false, "Inspect MX, SPF, DMARC, MTA-STS, and TLS reporting")
	dnsServer := flags.String("dns-server", "", "DNS resolver for CAA, TLSA, HTTPS, TTL, and DNSSEC AD checks (default: system resolver)")
	httpEnabled := flags.Bool("http", false, "Enable bounded HTTP security inspection")
	var httpPaths httpPathList
	flags.Var(&httpPaths, "http-path", "HTTPS path to inspect (repeatable; default /)")
	httpTimeout := flags.Duration("http-timeout", 10*time.Second, "Timeout for each HTTP request")
	httpMaxRedirects := flags.Int("http-max-redirects", 10, "Maximum HTTP redirect hops")
	httpMaxBody := flags.Int64("http-max-body", 1<<20, "Maximum decoded response bytes to read and discard")
	var httpAllowedHosts httpHostnameList
	flags.Var(&httpAllowedHosts, "http-allow-redirect-host", "Allow redirects to this hostname (repeatable)")
	versionOutput := flags.Bool("version", false, "Print version information and exit")
	schemaCapabilitiesOutput := flags.Bool("schema-capabilities", false, "Print JSON schema capabilities and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *versionOutput {
		if _, err := fmt.Fprintf(output, "mpdc %s\n", version); err != nil {
			return 1
		}
		return 0
	}
	if *schemaCapabilitiesOutput {
		if err := writeSchemaCapabilities(output); err != nil {
			fmt.Fprintf(errorOutput, "Error encoding schema capabilities: %v\n", err)
			return 1
		}
		return 0
	}

	if *jsonOutput && *markdownOutput {
		fmt.Fprintln(errorOutput, "Error: -json and -markdown flags are mutually exclusive.")
		return 1
	}
	if err := validateHTTPFlagValues(*httpTimeout, *httpMaxRedirects, *httpMaxBody, httpPaths); err != nil {
		fmt.Fprintf(errorOutput, "Error: %v\n", err)
		return 1
	}

	if *scanTimeout <= 0 || *concurrency < 1 || *concurrency > maxConcurrency {
		fmt.Fprintln(errorOutput, "Error: -scan-timeout must be positive and -concurrency must be between 1 and 64.")
		return 1
	}
	hostnames := flags.Args()

	if input != nil {
		hosts, err := readStandardInput(ctx, input)
		if err != nil {
			fmt.Fprintf(errorOutput, "Error reading stdin: %v\n", err)
			return 1
		}
		hostnames = append(hostnames, hosts...)
	}

	if *hostFile != "" {
		f, err := os.Open(*hostFile)
		if err != nil {
			fmt.Fprintf(errorOutput, "Error opening file %s: %v\n", *hostFile, err)
			return 1
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
			fmt.Fprintf(errorOutput, "Error reading file %s: %v\n", *hostFile, err)
			return 1
		}
	}

	if len(hostnames) == 0 {
		fmt.Fprintln(errorOutput, "Usage: mpdc [options] <hostname>...")
		flags.PrintDefaults()
		return 1
	}

	paths := []string(httpPaths)
	if len(paths) == 0 {
		paths = []string{"/"}
	}
	opts := options{
		concurrency: *concurrency,
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
	ctx, cancel := context.WithTimeout(ctx, *scanTimeout)
	defer cancel()
	results := make([]Result, 0, len(hostnames))
	for _, host := range hostnames {
		results = append(results, inspector.inspectHost(ctx, normalizeHostname(host), opts))
	}

	if *jsonOutput {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(errorOutput, "Error encoding JSON: %v\n", err)
			return 1
		}
		if _, err := fmt.Fprintln(output, string(data)); err != nil {
			fmt.Fprintf(errorOutput, "Error writing JSON: %v\n", err)
			return 1
		}
	} else if *markdownOutput {
		printMarkdown(output, results)
	} else {
		for _, result := range results {
			printResult(output, result)
		}
	}
	if ctx.Err() != nil {
		return 1
	}
	return 0
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

// Inherited stdin may use a blocking OS read that Close cannot interrupt. Let
// cancellation return to main (which exits the process) without waiting for that
// read. The buffered channel also lets the reader finish if input later resumes.
func readStandardInput(ctx context.Context, input io.Reader) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type inputResult struct {
		hosts []string
		err   error
	}
	done := make(chan inputResult, 1)
	go func() {
		var result inputResult
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			result.hosts = append(result.hosts, strings.Fields(scanner.Text())...)
			if ctx.Err() != nil {
				break
			}
		}
		result.err = scanner.Err()
		done <- result
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		return result.hosts, result.err
	}
}
