# mpdc — agent guidance

## What this is

A standard-library-only Go CLI tool (`mpdc`) that inspects DNS and TLS for given hostnames and can optionally perform bounded passive HTTP security inspection.

## Source layout

- `main.go` — CLI, scan-wide budget, signal cancellation, and capability preflight
- `scan.go`, `resolver.go` — scan orchestration and bounded system lookups
- `results.go` — shared JSON result types and compatibility fields
- `dns.go`, `dns_wire.go`, `dns_records.go` — DNS inspection, wire client, and record parsing
- `tls.go`, `certificate.go` — bounded endpoint workers, TLS probes, certificate diagnostics
- `findings.go`, `tlsa.go` — findings and per-endpoint TLSA evidence
- `mail.go` — mail DNS inspection
- `output.go`, `address.go`, `helpers.go` — rendering and shared helpers
- `http.go` — HTTP option validation, result types, scanner orchestration, and SSRF address policy
- `http_client.go` — bounded requests, pinned validated-address dialing, and manual redirects
- `http_headers.go` — browser-security header parsing and findings
- `http_cookies.go` — redacted cookie attribute parsing and findings
- `http_securitytxt.go` — RFC 9116 parsing and findings
- `*_test.go`, `testdata/` — offline regression tests, DNS fuzz targets, and schema fixtures
- `.github/workflows/verify.yml` — Linux/macOS checks and Linux fuzz smoke tests
- `mpdc` — prebuilt arm64 macOS binary, checked in
- No Makefile, external dependencies, or non-default formatter configuration

## Build

```bash
go build -o mpdc
```

Build to a temporary path during verification so the checked-in binary is not
updated incidentally:

```bash
go test -race ./...
go vet ./...
go build -o /tmp/mpdc .
```

## Usage

```bash
mpdc example.com                      # plain text (default)
mpdc -json example.com                # JSON output
mpdc -markdown example.com            # Markdown table
mpdc -http example.com                # add bounded HTTP security inspection
mpdc -http -http-path /login example.com
cat hosts.txt | mpdc                 # read from stdin
mpdc -file hosts.txt                 # read from file
mpdc -json host1 host2               # multiple hostnames
```

Options use the Go flag package's single-hyphen form and must appear before the
first hostname. `-json` and `-markdown` are mutually exclusive. HTTP mode is
opt-in; without `-http`, network behaviour remains DNS/TLS-only.

## Tests and verification

Tests do not use public internet services. Some use loopback `httptest` servers,
so their environment must permit local listeners.

```bash
gofmt -w *.go
go test -race ./...
go vet ./...
go build -o /tmp/mpdc .
/tmp/mpdc -version
/tmp/mpdc -h
git diff --check
```

## Key callouts

- **No external dependencies** — `go.mod` lists only `go 1.26.3`, no `go.sum`.
- **CI** — GitHub Actions runs offline race tests, vet, formatting, builds, and DNS fuzz smoke tests.
- **Bounded scans** — preserve shared context propagation, the scan-wide timeout, and the endpoint worker limit. Canceled work is incomplete, not proof of a remote failure.
- **Schema 2** — keep legacy fields and fixture baselines stable; new evidence fields are optional. TLSA findings are per endpoint, and unavailable evidence must not become a mismatch.
- **Binary is committed** — `mpdc` is a Mach-O arm64 binary that can be used directly.
- **HTTP safety boundary** — keep redirects manual, validate and pin every resolved address before dialing, never weaken production TLS verification, and never retain bodies or cookie values.
