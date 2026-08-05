# mpdc

`mpdc` is a small command-line tool for inspecting the DNS and TLS configuration
of one or more hostnames.

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
  algorithm, usages, and revocation endpoints; and
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
| `-scan-ciphers` | Enumerate accepted TLS 1.0–1.2 cipher suites. This performs many extra connections. |
| `-mail` | Inspect MX, SPF, DMARC, MTA-STS, and SMTP TLS reporting DNS records. |
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
object includes `"schema_version": 1`. Consumers should check this value before
processing a result and reject schema versions they do not support.

### Print the version

```sh
mpdc -version
```

This prints the program name and semantic version, for example `mpdc 0.1.0`.
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

## License

No license file is currently included in this repository.
