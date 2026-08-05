# mpdc — agent guidance

## What this is

A standard-library-only Go CLI tool (`mpdc`) that inspects DNS and TLS for given hostnames and can optionally perform bounded passive HTTP security inspection.

## Source layout

- `main.go` — CLI, DNS, TLS, output, and shared result types
- `http.go` — HTTP option validation, result types, scanner orchestration, and SSRF address policy
- `http_client.go` — bounded requests, pinned validated-address dialing, and manual redirects
- `http_headers.go` — browser-security header parsing and findings
- `http_cookies.go` — redacted cookie attribute parsing and findings
- `http_securitytxt.go` — RFC 9116 parsing and findings
- `http*_test.go` — offline table-driven/unit tests using injected resolution and `httptest`
- `mpdc` — prebuilt arm64 macOS binary, checked in
- No CI, Makefile, external dependencies, or non-default formatter configuration

## Build

```bash
go build -o mpdc
```

Build to a temporary path during verification so the checked-in binary is not
updated incidentally:

```bash
go test ./...
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
go test ./...
go vet ./...
go build -o /tmp/mpdc .
/tmp/mpdc -version
/tmp/mpdc -h
git diff --check
```

## Key callouts

- **No external dependencies** — `go.mod` lists only `go 1.26.3`, no `go.sum`.
- **No CI / Makefile / formatter config** — all conventions are Go defaults.
- **Binary is committed** — `mpdc` is a Mach-O arm64 binary that can be used directly.
- **HTTP safety boundary** — keep redirects manual, validate and pin every resolved address before dialing, never weaken production TLS verification, and never retain bodies or cookie values.
