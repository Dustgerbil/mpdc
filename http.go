package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxHTTPPaths            = 10
	maxHTTPResponseHeaders  = 128 << 10
	maxSecurityTXTBodyBytes = 64 << 10
)

type HTTPScanOptions struct {
	Enabled              bool
	Paths                []string
	Timeout              time.Duration
	MaxRedirects         int
	MaxBodyBytes         int64
	AllowedRedirectHosts []string
}

type HTTPInspection struct {
	Enabled        bool              `json:"enabled"`
	CleartextProbe HTTPPageResult    `json:"cleartext_probe"`
	Pages          []HTTPPageResult  `json:"pages"`
	SecurityTXT    SecurityTXTResult `json:"security_txt"`
	Findings       []Finding         `json:"findings,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
}

type HTTPPageResult struct {
	RequestedURL    string              `json:"requested_url"`
	FinalURL        string              `json:"final_url,omitempty"`
	StatusCode      int                 `json:"status_code,omitempty"`
	HTTPProtocol    string              `json:"http_protocol,omitempty"`
	RemoteIP        string              `json:"remote_ip,omitempty"`
	ContentType     string              `json:"content_type,omitempty"`
	ContentLength   int64               `json:"content_length"`
	BytesRead       int64               `json:"bytes_read"`
	BodyTruncated   bool                `json:"body_truncated"`
	RedirectChain   []RedirectHop       `json:"redirect_chain,omitempty"`
	SecurityHeaders SecurityHeaders     `json:"security_headers"`
	Cookies         []CookieObservation `json:"cookies,omitempty"`
	Findings        []Finding           `json:"findings,omitempty"`
	Error           string              `json:"error,omitempty"`
	finalURLRaw     string
}

type RedirectHop struct {
	Cookies     []CookieObservation `json:"cookies,omitempty"`
	FromURL     string              `json:"from_url"`
	StatusCode  int                 `json:"status_code"`
	Location    string              `json:"location"`
	ResolvedURL string              `json:"resolved_url,omitempty"`
	Followed    bool                `json:"followed"`
	StopReason  string              `json:"stop_reason,omitempty"`
}

type SecurityHeaders struct {
	StrictTransportSecurity         []string                `json:"strict_transport_security,omitempty"`
	HSTSMaxAge                      *int64                  `json:"hsts_max_age,omitempty"`
	HSTSIncludeSubDomains           bool                    `json:"hsts_include_subdomains"`
	HSTSPreload                     bool                    `json:"hsts_preload"`
	ContentSecurityPolicy           []string                `json:"content_security_policy,omitempty"`
	ContentSecurityPolicyReportOnly []string                `json:"content_security_policy_report_only,omitempty"`
	XFrameOptions                   []string                `json:"x_frame_options,omitempty"`
	XContentTypeOptions             []string                `json:"x_content_type_options,omitempty"`
	ReferrerPolicy                  []string                `json:"referrer_policy,omitempty"`
	PermissionsPolicy               []string                `json:"permissions_policy,omitempty"`
	SensitivePermissions            []PermissionObservation `json:"sensitive_permissions,omitempty"`
	CrossOriginOpenerPolicy         []string                `json:"cross_origin_opener_policy,omitempty"`
	CrossOriginEmbedderPolicy       []string                `json:"cross_origin_embedder_policy,omitempty"`
	CrossOriginResourcePolicy       []string                `json:"cross_origin_resource_policy,omitempty"`
	CacheControl                    []string                `json:"cache_control,omitempty"`
	Pragma                          []string                `json:"pragma,omitempty"`
	Server                          []string                `json:"server,omitempty"`
	XPoweredBy                      []string                `json:"x_powered_by,omitempty"`
	AccessControlAllowOrigin        []string                `json:"access_control_allow_origin,omitempty"`
	AccessControlAllowCredentials   []string                `json:"access_control_allow_credentials,omitempty"`
}

type PermissionObservation struct {
	Feature   string   `json:"feature"`
	Allowlist []string `json:"allowlist,omitempty"`
	Valid     bool     `json:"valid"`
}

type CookieObservation struct {
	Name           string   `json:"name"`
	Secure         bool     `json:"secure"`
	HTTPOnly       bool     `json:"http_only"`
	SameSite       string   `json:"same_site,omitempty"`
	Path           string   `json:"path,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	Partitioned    bool     `json:"partitioned"`
	HostPrefix     bool     `json:"host_prefix"`
	SecurePrefix   bool     `json:"secure_prefix"`
	AttributeNames []string `json:"attribute_names,omitempty"`
}

type SecurityTXTResult struct {
	RequestedURL       string     `json:"requested_url"`
	FinalURL           string     `json:"final_url,omitempty"`
	Present            bool       `json:"present"`
	StatusCode         int        `json:"status_code,omitempty"`
	ContentType        string     `json:"content_type,omitempty"`
	UTF8Valid          bool       `json:"utf8_valid"`
	Contacts           []string   `json:"contacts,omitempty"`
	Expires            *time.Time `json:"expires,omitempty"`
	Canonical          []string   `json:"canonical,omitempty"`
	Policy             []string   `json:"policy,omitempty"`
	Encryption         []string   `json:"encryption,omitempty"`
	PreferredLanguages []string   `json:"preferred_languages,omitempty"`
	Signed             bool       `json:"signed"`
	UnknownFieldNames  []string   `json:"unknown_field_names,omitempty"`
	Findings           []Finding  `json:"findings,omitempty"`
	Error              string     `json:"error,omitempty"`
}

type httpPathList []string

func (values *httpPathList) String() string { return strings.Join(*values, ",") }

func (values *httpPathList) Set(value string) error {
	if len(*values) >= maxHTTPPaths {
		return fmt.Errorf("-http-path may be supplied at most %d times", maxHTTPPaths)
	}
	if err := validateHTTPPath(value); err != nil {
		return err
	}
	*values = append(*values, value)
	return nil
}

type httpHostnameList []string

func (values *httpHostnameList) String() string { return strings.Join(*values, ",") }

func (values *httpHostnameList) Set(value string) error {
	host, err := normalizeHTTPHostname(value)
	if err != nil {
		return fmt.Errorf("invalid -http-allow-redirect-host %q: %w", value, err)
	}
	*values = append(*values, host)
	return nil
}

func validateHTTPFlagValues(timeout time.Duration, redirects int, bodyBytes int64, paths []string) error {
	if timeout <= 0 {
		return errors.New("-http-timeout must be greater than zero")
	}
	if redirects < 0 || redirects > 50 {
		return errors.New("-http-max-redirects must be between 0 and 50")
	}
	if bodyBytes <= 0 || bodyBytes > 64<<20 {
		return errors.New("-http-max-body must be between 1 and 67108864 bytes")
	}
	if len(paths) > maxHTTPPaths {
		return fmt.Errorf("-http-path may be supplied at most %d times", maxHTTPPaths)
	}
	for _, path := range paths {
		if err := validateHTTPPath(path); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTPPath(value string) error {
	if value == "" || value[0] != '/' || strings.HasPrefix(value, "//") {
		return fmt.Errorf("invalid -http-path %q: value must be an absolute path beginning with one /", value)
	}
	if strings.Contains(value, "#") {
		return fmt.Errorf("invalid -http-path %q: fragments are not allowed", value)
	}
	if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("invalid -http-path %q: control characters are not allowed", value)
	}
	u, err := url.ParseRequestURI(value)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("invalid -http-path %q: schemes, hosts, userinfo, fragments, and malformed escapes are not allowed", value)
	}
	if strings.IndexFunc(u.Path, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("invalid -http-path %q: percent-encoded control characters are not allowed", value)
	}
	return nil
}

func normalizeHTTPHostname(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || strings.ContainsAny(value, "/:@[]?#") {
		return "", errors.New("expected a bare hostname without a port or URL components")
	}
	if !utf8.ValidString(value) {
		return "", errors.New("hostname is not valid UTF-8")
	}
	for _, r := range value {
		if r > 0x7f {
			return "", errors.New("use the ASCII punycode form for internationalized hostnames")
		}
		if !(r == '-' || r == '.' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return "", errors.New("hostname contains an invalid character")
		}
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("hostname contains an invalid DNS label")
		}
	}
	if len(value) > 253 {
		return "", errors.New("hostname is too long")
	}
	return value, nil
}

type httpResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type httpDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type httpScanner struct {
	options   HTTPScanOptions
	resolver  httpResolver
	dialer    httpDialer
	tlsConfig *tls.Config
	now       func() time.Time
}

func newHTTPScanner(options HTTPScanOptions) *httpScanner {
	return &httpScanner{
		options:  options,
		resolver: net.DefaultResolver,
		dialer:   &net.Dialer{Timeout: options.Timeout},
		now:      time.Now,
	}
}

func (scanner *hostScanner) addHTTPInspection(ctx context.Context, result *Result, options HTTPScanOptions) {
	if !options.Enabled {
		return
	}
	inspection := scanner.newHTTP(options).inspect(ctx, result.Hostname)
	result.HTTP = &inspection
	result.Findings = append(result.Findings, inspection.Findings...)
	result.Findings = deduplicateFindings(result.Findings)
}

func (scanner *httpScanner) inspect(ctx context.Context, host string) HTTPInspection {
	inspection := HTTPInspection{Enabled: true}
	normalized, err := normalizeHTTPHostname(host)
	if err != nil {
		inspection.Errors = append(inspection.Errors, fmt.Sprintf("HTTP inspection rejected hostname %q: %v", host, err))
		return inspection
	}
	allowed := map[string]bool{normalized: true}
	for _, item := range scanner.options.AllowedRedirectHosts {
		allowed[item] = true
	}

	clearURL := "http://" + normalized + "/"
	inspection.CleartextProbe, _ = scanner.fetchPage(ctx, clearURL, normalized, allowed, scanner.options.MaxBodyBytes, false)
	inspection.CleartextProbe.Findings = append(inspection.CleartextProbe.Findings,
		evaluateCleartextRedirect(inspection.CleartextProbe)...)

	for _, path := range scanner.options.Paths {
		page, _ := scanner.fetchPage(ctx, "https://"+normalized+path, normalized, allowed, scanner.options.MaxBodyBytes, true)
		inspection.Pages = append(inspection.Pages, page)
	}

	inspection.SecurityTXT = scanner.inspectSecurityTXT(ctx, normalized, allowed)
	inspection.Findings = append(inspection.Findings, inspection.CleartextProbe.Findings...)
	if inspection.CleartextProbe.Error != "" {
		inspection.Errors = append(inspection.Errors, inspection.CleartextProbe.Error)
	}
	for _, page := range inspection.Pages {
		inspection.Findings = append(inspection.Findings, page.Findings...)
		if page.Error != "" {
			inspection.Errors = append(inspection.Errors, page.Error)
		}
	}
	inspection.Findings = append(inspection.Findings, inspection.SecurityTXT.Findings...)
	if inspection.SecurityTXT.Error != "" {
		inspection.Errors = append(inspection.Errors, inspection.SecurityTXT.Error)
	}
	inspection.Findings = deduplicateFindings(inspection.Findings)
	inspection.Errors = deduplicateStrings(inspection.Errors)
	return inspection
}

func evaluateCleartextRedirect(page HTTPPageResult) []Finding {
	if page.Error != "" || page.StatusCode == 0 {
		return nil
	}
	final, err := url.Parse(page.FinalURL)
	if err == nil && final.Scheme == "https" && len(page.RedirectChain) > 0 {
		return nil
	}
	return []Finding{finding("HTTP_NO_HTTPS_REDIRECT", "warning",
		fmt.Sprintf("%s did not complete a redirect from cleartext HTTP to HTTPS; final URL was %s with status %d.", page.RequestedURL, valueOrDash(page.FinalURL), page.StatusCode))}
}

func deduplicateFindings(values []Finding) []Finding {
	seen := make(map[string]bool)
	result := make([]Finding, 0, len(values))
	for _, value := range values {
		key := value.Code + "\x00" + value.Severity + "\x00" + value.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}
	return result
}

func deduplicateStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

// These tables are maintained from the IANA IPv4 and IPv6 Special-Purpose
// Address Registries (last reviewed 2026-08-05). Parent prefixes with a small
// number of globally reachable exceptions are denied here and explicitly
// allowed below. IPv6 is additionally restricted to 2000::/3, the IANA global
// unicast allocation, so newly assigned non-global space fails closed.
var nonGlobalHTTPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	// Translation prefixes can embed otherwise-blocked IPv4 destinations.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var globalHTTPPrefixExceptions = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.9/32"),
	netip.MustParsePrefix("192.0.0.10/32"),
	netip.MustParsePrefix("2001:1::1/128"),
	netip.MustParsePrefix("2001:1::2/128"),
	netip.MustParsePrefix("2001:1::3/128"),
	netip.MustParsePrefix("2001:3::/32"),
	netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:30::/28"),
}

var globalIPv6HTTPPrefix = netip.MustParsePrefix("2000::/3")

func blockedHTTPAddress(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	for _, prefix := range globalHTTPPrefixExceptions {
		if prefix.Contains(address) {
			return false
		}
	}
	if address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() ||
		!address.IsGlobalUnicast() {
		return true
	}
	if address.Is6() && !globalIPv6HTTPPrefix.Contains(address) {
		return true
	}
	for _, prefix := range nonGlobalHTTPPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func allowedHTTPPort(u *url.URL) bool {
	port := u.Port()
	if port == "" {
		return true
	}
	return u.Scheme == "http" && port == "80" || u.Scheme == "https" && port == "443"
}

func normalizedURLHost(u *url.URL) (string, error) {
	if u.User != nil {
		return "", errors.New("URL userinfo is not allowed")
	}
	return normalizeHTTPHostname(u.Hostname())
}

func sortedIPs(addresses []net.IPAddr) []net.IP {
	values := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, append(net.IP(nil), address.IP...))
	}
	sort.Slice(values, func(i, j int) bool { return values[i].String() < values[j].String() })
	return values
}

func httpURLPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func canonicalURL(u *url.URL) string {
	copyURL := *u
	copyURL.Scheme = strings.ToLower(copyURL.Scheme)
	host := strings.ToLower(strings.TrimSuffix(copyURL.Hostname(), "."))
	port := copyURL.Port()
	if port != "" && !(copyURL.Scheme == "http" && port == "80") && !(copyURL.Scheme == "https" && port == "443") {
		host = net.JoinHostPort(host, port)
	}
	copyURL.Host = host
	copyURL.Fragment = ""
	return copyURL.String()
}

func int64Limit(value, maximum int64) int64 {
	if value < maximum {
		return value
	}
	return maximum
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}
