# mpdc — agent guidance

## What this is

A single-file Go CLI tool (`mpdc`) that inspects DNS and TLS for given hostnames: resolves CNAME/IPs, connects via TLS on `:443`, and prints certificate details.

## Source layout

- `main.go` — entire application (stdlib only, no external deps)
- `mpdc` — prebuilt arm64 macOS binary, checked in
- No tests, no CI, no lint/format config, no Makefile

## Build

```bash
go build -o mpdc
```

## Usage

```bash
mpdc example.com                     # plain text (default)
mpdc example.com --json              # JSON output
mpdc example.com --markdown          # Markdown table
cat hosts.txt | mpdc                 # read from stdin
mpdc --file hosts.txt                # read from file
mpdc host1 host2 --json              # multiple hostnames
```

`--json` and `--markdown` are mutually exclusive.

## No test suite

No tests exist. Nothing to run.

## Key callouts

- **No external dependencies** — `go.mod` lists only `go 1.26.3`, no `go.sum`.
- **No CI / Makefile / formatter config** — all conventions are Go defaults.
- **Binary is committed** — `mpdc` is a Mach-O arm64 binary that can be used directly.
