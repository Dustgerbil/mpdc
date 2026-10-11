# mpdc

`mpdc` is a small command-line tool for inspecting the DNS and TLS configuration
of one or more hostnames. An opt-in HTTP mode adds bounded, passive inspection of
redirects, response headers, cookie attributes, and `security.txt`.

For each hostname, it:

- resolves IPv4, IPv6, canonical-name, CAA, TLSA, and HTTPS/SVCB records;
- reports DNS TTLs and whether the selected resolver set the DNSSEC
  Authenticated Data bit;
- connects directly to every resolved address while preserving the hostname
  for SNI and certificate verification;
- reports trust, hostname, and certificate-time validation independently;
- actively checks support for TLS 1.0 through TLS 1.3;
- reports the negotiated cipher suite, key-exchange group, ALPN, OCSP staple,
  Certificate Transparency SCT count, and certificate chains;
- displays certificate fingerprints, serial numbers, key strength, signature
  algorithm, usages, and revocation endpoints;
- optionally records bounded HTTP redirects, security headers, redacted cookie
  attributes, and RFC 9116 `security.txt`; and
- emits stable, severity-labelled findings for automation.

The tool uses only the Go standard library.

## Requirements

- macOS on Apple silicon to use the checked-in `mpdc` binary, or
- Go 1.26.3 or later to build from source.

## Installation

The repository includes a prebuilt arm64 macOS binary. Make it available on
your `PATH`, for example:

```sh
install -m 0755 mpdc /usr/local/bin/mpdc
```

Alternatively, build it from source:

```sh
go build -o mpdc
```

## Usage

```text
mpdc [options] <hostname>...
```

Options must appear before the first hostname.

| Option | Description |
| --- | --- |
| `-json` | Output results as formatted JSON. |
| `-markdown` | Output results as a Markdown table. |
| `-file <path>` | Read hostnames from a text file. |
| `-dns-server <address>` | Use this resolver for advanced DNS queries. Port 53 is assumed when omitted. |
| `-scan-timeout <duration>` | Total network scan budget across all hostnames; default `5m`. |
| `-concurrency <n>` | Maximum simultaneous endpoint inspections; default `8`, range `1`–`64`. |
| `-scan-ciphers` | Enumerate accepted TLS 1.0–1.2 cipher suites. This performs many extra connections. |
| `-mail` | Inspect MX, SPF, DMARC, MTA-STS, and SMTP TLS reporting DNS records. |
| `-http` | Enable bounded HTTP security inspection. |
| `-http-path <path>` | Add an HTTPS path to inspect; repeatable, maximum 10. |
| `-http-timeout <duration>` | Set each HTTP request timeout; default `10s`. |
| `-http-max-redirects <n>` | Set the maximum redirect hops; default `10`. |
| `-http-max-body <bytes>` | Set the decoded page-body read/discard limit; default 1 MiB. |
| `-http-allow-redirect-host <hostname>` | Allow redirects to a named hostname; repeatable. |
| `-schema-capabilities` | Print result-schema capabilities as JSON and exit. |
| `-version` | Print the `mpdc` version and exit. |

`-json` and `-markdown` are mutually exclusive.

### Inspect one hostname

```sh
mpdc example.com
```

### Inspect multiple hostnames

```sh
mpdc example.com www.example.com
```

### Produce JSON

```sh
mpdc -json example.com
```

JSON output remains an array with one object per requested hostname. Every
object includes `"schema_version": 2`. Schema 2 preserves all schema-1 fields
and meanings and adds an optional `http` object. The object is omitted when
`-http` is not selected. Consumers should check the schema value before
processing a result and reject schema versions they do not support.

### Print schema capabilities

```sh
mpdc -schema-capabilities
```

This performs no inspection and prints the current result schema version and
the stable capability identifiers implemented by the binary. Each capability
states whether it is enabled by default and, for opt-in capabilities, which
flag enables it:

```json
{
  "schema_version": 2,
  "capabilities": [
    { "name": "dns", "enabled_by_default": true },
    { "name": "tls", "enabled_by_default": true },
    { "name": "mail", "enabled_by_default": false, "flag": "-mail" },
    { "name": "http", "enabled_by_default": false, "flag": "-http" }
  ]
}
```

### Print the version

```sh
mpdc -version
```

This prints the program name and semantic version, for example `mpdc 0.2.0`.
Release builds can override the source version with
`-ldflags "-X main.version=<version>"`.

### Produce a Markdown table

```sh
mpdc -markdown example.com www.example.com
```

### Read hostnames from standard input

```sh
printf '%s\n' example.com www.example.com | mpdc
```

### Read hostnames from a file

Create a whitespace-separated list of hostnames:

```text
example.com
www.example.com
```

Then run:

```sh
mpdc -file hosts.txt
```

Command-line arguments, standard input, and `-file` can be used together.

## Example output

Plain-text output has the following form (addresses and certificate values will
vary):

```text
Hostname: example.com
  A records:      192.0.2.10
  DNS resolver:   127.0.0.1:53
  DNSSEC status:  resolver_validated
  DNS A     TTL:  300    example.com -> 192.0.2.10
  CAA:            example.com 0 issue "example-ca.test" (TTL 300)

  Endpoint 192.0.2.10 (IPv4, documentation)
    TCP reachable:       true
    TLS handshake:       true
    Certificate valid:   true
    Chain trusted:       true
    Hostname match:      true
    Negotiated TLS:      TLS 1.3
    Supported TLS:       TLS 1.2, TLS 1.3
    Cipher suite:        TLS_AES_128_GCM_SHA256
    Key exchange:        X25519MLKEM768
    ALPN:                h2
    OCSP staple:         true
    SCTs:                2
    Subject:             CN=example.com
    Validity:            2026-07-01T00:00:00Z to 2026-09-29T23:59:59Z (66 days remaining; valid)
    Public key:          ECDSA, 256 bits, P-256
    Signature algorithm: ECDSA-SHA256
    SHA-256 fingerprint: 00:11:22:...
```

DNS or HTTPS failures are reported in the result for the affected hostname, so
other hostnames can still be inspected.

### Scan budget and partial results

All hostnames in one invocation share a `-scan-timeout` budget (default five
minutes), starting after input has been read. Hosts are processed in input order;
up to `-concurrency` endpoints within the current host are inspected in parallel.
Each worker runs that endpoint's TLS and optional cipher probes sequentially.
DNS, TLS, mail and HTTP operations all inherit the remaining budget. System DNS
lookups, advanced DNS exchanges (including TCP fallback), and TLS connections also
have an individual five-second limit; HTTP requests retain `-http-timeout`.

```sh
mpdc -scan-timeout 2m -concurrency 4 -http -json example.com www.example.com
mpdc -scan-timeout 15m -scan-ciphers example.com
```

On timeout, Ctrl-C, or SIGTERM, completed evidence is retained, unfinished hosts
and endpoints have `"incomplete": true`, and affected hosts include the informational
`SCAN_INCOMPLETE` finding. No new network work starts after cancellation. The
output still contains an entry for every input hostname. An interrupted scan
exits with status 1; ordinary completed scans retain status 0 even when they
contain security findings or individual network errors. Preflight flags
(`-version`, `-schema-capabilities`, and `-h`) perform no scanning.

### Evidence availability

Schema 2 retains all existing fields and adds optional evidence fields:

- `dns.nameserver_status`: `available` or `unavailable`. A failed or malformed NS
  lookup does not trigger `DNS_SINGLE_NAMESERVER`.
- `endpoints[].tlsa_status`: `matched`, `mismatched`, or `unavailable` when
  authenticated TLSA records are present. Each endpoint is compared against all
  supported, well-formed authenticated associations; any one may match (including
  during certificate rotation). Mismatches identify the affected address.
- `DANE_TLSA_UNAVAILABLE` is informational when no certificate or usable
  authenticated association is available. Missing evidence is not a mismatch.
- `http.*.redirect_chain[].cookies` retains redacted attributes for each redirect
  response, including redirects that were stopped. Final-response `cookies`
  retains its original meaning. HTTPS cookie findings cover redirect and error
  responses as well as successful pages.

The legacy record-level `matches_presented_chain` remains an any-endpoint
observation; use endpoint status and findings to detect a partially misconfigured
hostname. These comparisons describe certificate association evidence, not a
complete DANE trust-path validation.

With `-http`, plain text also includes a bounded summary such as:

```text
  HTTP security
    Cleartext probe: http://example.com/ -> https://example.com/ (status 200)
    HTTPS page:     https://example.com/ -> https://example.com/ (status 200, HTTP/2.0, remote 203.0.113.10, bytes 1256, truncated=false)
    security.txt:   https://example.com/.well-known/security.txt (present=true, status=200, contacts=1)
```

## Findings

Findings use stable codes and one of three severities: `critical`, `warning`,
or `info`. Examples include:

- `CERT_EXPIRED`
- `CERT_HOSTNAME_MISMATCH`
- `CERT_UNTRUSTED`
- `CERT_MUST_STAPLE_MISSING`
- `CERT_WEAK_RSA_KEY`
- `TLS_LEGACY_VERSION_SUPPORTED`
- `TLS_WEAK_CIPHER_SUPPORTED`
- `ENDPOINT_CERT_MISMATCH`
- `ENDPOINT_TLS_POLICY_MISMATCH`
- `DANE_TLSA_MISMATCH`
- `DNSSEC_LEGACY_ALGORITHM`

The findings are intended to be transparent assertions, not an opaque
letter-grade score.

## Advanced DNS behaviour

Advanced DNS queries use a small built-in DNS wire client, keeping the program
standard-library-only. The resolver is taken from the first `nameserver` entry
in `/etc/resolv.conf` unless `-dns-server` is supplied.

`dnssec_status: resolver_validated` means the selected recursive resolver set
the DNS Authenticated Data bit. The program does not perform a complete local
DNSSEC signature validation. `not_validated` can mean either that the zone is
unsigned or that the selected resolver did not validate it.

The zone is derived from its SOA response. The output then includes
nameservers and their addresses, DS and DNSKEY algorithms and key tags, and
the inception and expiration times of returned RRSIG records.

TLSA certificate matching supports selectors 0 and 1 and matching types 0, 1,
and 2. A TLSA mismatch is raised as a critical finding only when the resolver
authenticated the TLSA response.

CAA records are shown as the current policy at the first applicable name in
the DNS hierarchy. They are not used to declare an already-issued certificate
invalid because the CAA policy might have changed since issuance.

## Notes

- Pass bare hostnames such as `example.com`, without a URL scheme, path, or
  port.
- TLS connections and DNS exchanges have a five-second timeout.
- Certificate verification uses Go's system trust store and hostname
  validation.
- IP address ordering depends on the system DNS resolver.
- A failed verified handshake is retried without verification solely to
  retrieve diagnostic certificate details. Such a result remains explicitly
  marked untrusted.
- A local lack of IPv4 or IPv6 routing is reported as
  `LOCAL_NETWORK_UNAVAILABLE`, rather than as a remote server outage.
- OCSP output reports whether a stapled response was present; the response
  status is not parsed.
- `-mail` discovers the MTA-STS DNS record but does not download its HTTPS
  policy file.

## Optional HTTP security inspection

HTTP inspection is disabled by default, so a normal invocation retains the
DNS/TLS-only request behaviour. Enable it with `-http`:

```sh
mpdc -http example.com
mpdc -http -json example.com
mpdc -http -http-path / -http-path /login \
  -http-allow-redirect-host www.example.com -json example.com
```

For each hostname, HTTP mode sends bounded `GET` requests to:

- `http://hostname/` to observe the cleartext-to-HTTPS redirect chain;
- each explicitly configured path on `https://hostname` (default `/`); and
- `https://hostname/.well-known/security.txt`, with `/security.txt` checked only
  when the RFC 9116 location is absent.

Each redirect hop is recorded and validated before the next connection. Only
HTTP and HTTPS on ports 80 and 443 are permitted. Redirects are followed only
on the original hostname or a hostname explicitly listed with
`-http-allow-redirect-host`. Every destination is resolved before connection;
loopback, private, link-local, multicast, unspecified, documentation,
carrier-grade NAT, reserved, and metadata-style addresses are blocked. If any
resolved address is blocked, the destination is not contacted. Internationalized
hostnames must be supplied in their ASCII punycode form. A second egress gate at
the socket boundary accepts only literal, globally reachable addresses on TCP
ports 80 and 443. Deployments should retain an equivalent host, container, or
network firewall deny policy as an independent control; the process does not
attempt to reconfigure the operator's firewall.

The scanner records status, protocol, remote address, content metadata, bounded
byte counts, redirects, selected browser-security headers, redacted cookie
attributes, and parsed `security.txt` fields. Cookie values, raw `Set-Cookie`
headers, response bodies, page text, and raw `security.txt` content are never
included in output. URL userinfo and query parameter values are redacted while
query parameter names are retained for redirect comparison. Bodies are read only
to a configured decoded-byte limit and discarded.

HTTP mode does not crawl, discover subdomains or paths, execute JavaScript,
fetch page resources, authenticate, submit forms, replay cookies, fuzz, exploit,
or test CORS with an `Origin` header. It is a deterministic passive inspection,
not a vulnerability scanner, browser, or overall risk score.

### HTTP options and bounds

| Option | Description |
| --- | --- |
| `-http` | Enable HTTP security inspection. |
| `-http-path <path>` | Repeatable HTTPS path; defaults to `/`, requires an absolute path, maximum 10. |
| `-http-timeout <duration>` | Timeout for each request; default `10s`. |
| `-http-max-redirects <n>` | Maximum followed redirect hops; default `10`, maximum `50`. |
| `-http-max-body <bytes>` | Maximum decoded page bytes read and discarded; default 1 MiB, maximum 64 MiB. |
| `-http-allow-redirect-host <hostname>` | Repeatable hostname explicitly allowed as a redirect target. |

The `security.txt` body is always capped at the smaller of `-http-max-body` and
64 KiB. Response headers are capped at 128 KiB. No cookie jar is used. With one
default page and no redirects, HTTP mode makes three requests when the
well-known `security.txt` exists, or four when it is absent and the legacy
location is checked. Each configured path adds one initial request; followed
redirects add one request per hop up to the configured limit.

HTTP findings use the same `critical`, `warning`, and `info` severities as the
DNS/TLS findings and are aggregated into the top-level `findings` array. Stable
HTTP codes include:

- transport: `HTTP_NO_HTTPS_REDIRECT`, `HTTP_REDIRECT_TO_INSECURE`,
  `HTTP_REDIRECT_LOOP`, `HTTP_REDIRECT_LIMIT_REACHED`,
  `HTTP_REDIRECT_OUT_OF_SCOPE`, `HTTP_REDIRECT_UNSUPPORTED_SCHEME`, and
  `HTTP_TARGET_ADDRESS_BLOCKED`;
- HSTS: `HSTS_MISSING`, `HSTS_INVALID`, `HSTS_DISABLED`, and
  `HSTS_SHORT_MAX_AGE`;
- content policy and framing: `CSP_MISSING`, `CSP_NOT_ENFORCED`, `CSP_INVALID`,
  `CSP_UNSAFE_EVAL`, `CSP_UNSAFE_INLINE_SCRIPT`,
  `CSP_WILDCARD_SCRIPT_SOURCE`, `CLICKJACKING_PROTECTION_MISSING`, and
  `X_FRAME_OPTIONS_INVALID`;
- other headers: `NOSNIFF_MISSING`, `REFERRER_POLICY_MISSING`,
  `REFERRER_POLICY_UNSAFE_URL`, `PERMISSIONS_POLICY_MISSING`,
  `PERMISSIONS_POLICY_SENSITIVE_WILDCARD`, and `SERVER_VERSION_DISCLOSURE`;
- cookies: `COOKIE_SECURE_MISSING`, `COOKIE_HTTPONLY_MISSING`,
  `COOKIE_SAMESITE_MISSING`, `COOKIE_SAMESITE_NONE_WITHOUT_SECURE`, and
  `COOKIE_PREFIX_INVALID`; and
- RFC 9116: `SECURITY_TXT_MISSING`, `SECURITY_TXT_INVALID`,
  `SECURITY_TXT_EXPIRED`, `SECURITY_TXT_INSECURE_REDIRECT`, and
  `SECURITY_TXT_LEGACY_LOCATION`.

Absence of context-dependent controls such as Referrer Policy, Permissions
Policy, `HttpOnly`, and `SameSite` is informational. Passive CORS headers are
recorded without drawing a security conclusion because the request contains no
`Origin` header.

## Development and verification

The code uses the standard library only. Responsibilities are separated into
CLI (`main.go`), orchestration (`scan.go`), shared result types (`results.go`),
DNS transport/parsing (`dns_wire.go`, `dns_records.go`), DNS inspection (`dns.go`),
TLS/certificates (`tls.go`, `certificate.go`), findings (`findings.go`, `tlsa.go`),
mail (`mail.go`), rendering (`output.go`), and the `http*.go` modules.

Tests use injected dependencies and loopback servers, never public scan targets.
Allow local listeners when running them. Build to a temporary path to preserve
the checked-in macOS binary:

```sh
gofmt -w *.go
go test -race -cover ./...
go vet ./...
go build -o /tmp/mpdc .
/tmp/mpdc -version
/tmp/mpdc -schema-capabilities
git diff --check
```

DNS parser fuzzing is offline:

```sh
go test -run '^$' -fuzz '^FuzzDNSResponse$' -fuzztime=10s -parallel=2
go test -run '^$' -fuzz '^FuzzDNSName$' -fuzztime=10s -parallel=2
```

GitHub Actions runs formatting, race-enabled tests, vet and build/preflight checks
on Linux and macOS, plus short fuzz runs on Linux. Legacy JSON fixtures under
`testdata/` protect schema-2 field names, types, omission behaviour, and the
array-shaped output contract. They are baselines, not generated build artifacts.

## License

No license file is currently included in this repository.
