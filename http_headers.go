package main

import (
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func observeSecurityHeaders(header http.Header) SecurityHeaders {
	result := SecurityHeaders{
		StrictTransportSecurity:         header.Values("Strict-Transport-Security"),
		ContentSecurityPolicy:           header.Values("Content-Security-Policy"),
		ContentSecurityPolicyReportOnly: header.Values("Content-Security-Policy-Report-Only"),
		XFrameOptions:                   header.Values("X-Frame-Options"),
		XContentTypeOptions:             header.Values("X-Content-Type-Options"),
		ReferrerPolicy:                  header.Values("Referrer-Policy"),
		PermissionsPolicy:               header.Values("Permissions-Policy"),
		CrossOriginOpenerPolicy:         header.Values("Cross-Origin-Opener-Policy"),
		CrossOriginEmbedderPolicy:       header.Values("Cross-Origin-Embedder-Policy"),
		CrossOriginResourcePolicy:       header.Values("Cross-Origin-Resource-Policy"),
		CacheControl:                    header.Values("Cache-Control"),
		Pragma:                          header.Values("Pragma"),
		Server:                          header.Values("Server"),
		XPoweredBy:                      header.Values("X-Powered-By"),
		AccessControlAllowOrigin:        header.Values("Access-Control-Allow-Origin"),
		AccessControlAllowCredentials:   header.Values("Access-Control-Allow-Credentials"),
	}
	if len(result.StrictTransportSecurity) == 1 {
		if policy, err := parseHSTS(result.StrictTransportSecurity[0]); err == nil {
			result.HSTSMaxAge = &policy.maxAge
			result.HSTSIncludeSubDomains = policy.includeSubdomains
			result.HSTSPreload = policy.preload
		}
	}
	result.SensitivePermissions = observeSensitivePermissions(result.PermissionsPolicy)
	return result
}

func evaluateHTTPPage(page HTTPPageResult, secure bool) []Finding {
	if !secure || page.StatusCode < 200 || page.StatusCode >= 300 {
		return nil
	}
	var findings []Finding
	urlValue := page.FinalURL
	findings = append(findings, evaluateHSTS(urlValue, page.SecurityHeaders.StrictTransportSecurity)...)
	if exposesSoftwareVersion(page.SecurityHeaders.Server) || exposesSoftwareVersion(page.SecurityHeaders.XPoweredBy) {
		findings = append(findings, finding("SERVER_VERSION_DISCLOSURE", "info",
			fmt.Sprintf("%s exposes an explicit software version in Server or X-Powered-By.", urlValue)))
	}
	findings = append(findings, evaluateCookieFindings(urlValue, page.Cookies)...)
	if !isHTMLContentType(page.ContentType) {
		return findings
	}
	findings = append(findings, evaluateCSP(urlValue, page.SecurityHeaders.ContentSecurityPolicy,
		page.SecurityHeaders.ContentSecurityPolicyReportOnly)...)
	findings = append(findings, evaluateFraming(urlValue, page.SecurityHeaders.ContentSecurityPolicy,
		page.SecurityHeaders.XFrameOptions)...)
	if !headerHasToken(page.SecurityHeaders.XContentTypeOptions, "nosniff") {
		findings = append(findings, finding("NOSNIFF_MISSING", "warning",
			fmt.Sprintf("%s is an HTML document without X-Content-Type-Options: nosniff.", urlValue)))
	}
	findings = append(findings, evaluateReferrerPolicy(urlValue, page.SecurityHeaders.ReferrerPolicy)...)
	findings = append(findings, evaluatePermissionsPolicy(urlValue, page.SecurityHeaders.PermissionsPolicy)...)
	return findings
}

func isHTMLContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "text/html")
}

type hstsPolicy struct {
	maxAge            int64
	maxAgeSet         bool
	includeSubdomains bool
	preload           bool
}

func evaluateHSTS(urlValue string, values []string) []Finding {
	if len(values) == 0 {
		return []Finding{finding("HSTS_MISSING", "warning",
			fmt.Sprintf("%s returned no Strict-Transport-Security header over HTTPS.", urlValue))}
	}
	if len(values) != 1 {
		return []Finding{finding("HSTS_INVALID", "warning",
			fmt.Sprintf("%s returned %d Strict-Transport-Security field values; RFC 6797 requires one valid policy.", urlValue, len(values)))}
	}
	policy, err := parseHSTS(values[0])
	if err != nil {
		return []Finding{finding("HSTS_INVALID", "warning",
			fmt.Sprintf("%s returned an invalid Strict-Transport-Security policy: %v.", urlValue, err))}
	}
	if policy.maxAge == 0 {
		return []Finding{finding("HSTS_DISABLED", "warning",
			fmt.Sprintf("%s returned Strict-Transport-Security with max-age=0, disabling HSTS.", urlValue))}
	}
	if policy.maxAge < 15552000 {
		return []Finding{finding("HSTS_SHORT_MAX_AGE", "info",
			fmt.Sprintf("%s returned HSTS max-age=%d seconds, shorter than 180 days.", urlValue, policy.maxAge))}
	}
	return nil
}

func parseHSTS(value string) (hstsPolicy, error) {
	var result hstsPolicy
	seen := make(map[string]bool)
	for _, raw := range strings.Split(value, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, parameter, hasParameter := strings.Cut(raw, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if seen[name] {
			return result, fmt.Errorf("duplicate %s directive", name)
		}
		seen[name] = true
		switch name {
		case "max-age":
			if !hasParameter {
				return result, fmt.Errorf("max-age has no value")
			}
			parameter = strings.TrimSpace(parameter)
			if strings.HasPrefix(parameter, "\"") || strings.HasSuffix(parameter, "\"") {
				parameter = strings.Trim(parameter, "\"")
			}
			value, err := strconv.ParseInt(parameter, 10, 64)
			if err != nil || value < 0 {
				return result, fmt.Errorf("max-age is not a non-negative integer")
			}
			result.maxAge, result.maxAgeSet = value, true
		case "includesubdomains":
			if hasParameter {
				return result, fmt.Errorf("includeSubDomains must not have a value")
			}
			result.includeSubdomains = true
		case "preload":
			if hasParameter {
				return result, fmt.Errorf("preload must not have a value")
			}
			result.preload = true
		}
	}
	if !result.maxAgeSet {
		return result, fmt.Errorf("max-age is missing")
	}
	return result, nil
}

type cspPolicy map[string][]string

func parseCSP(value string) (cspPolicy, error) {
	policy := make(cspPolicy)
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("policy is empty")
	}
	for _, raw := range strings.Split(value, ";") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if !validCSPDirectiveName(name) || policy[name] != nil {
			return nil, fmt.Errorf("invalid or duplicate directive %q", name)
		}
		policy[name] = append([]string(nil), fields[1:]...)
	}
	if len(policy) == 0 {
		return nil, fmt.Errorf("policy has no directives")
	}
	return policy, nil
}

func validCSPDirectiveName(value string) bool {
	for _, r := range value {
		if !(r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return value != ""
}

func effectiveScriptSources(policy cspPolicy) ([]string, bool) {
	for _, directive := range []string{"script-src-elem", "script-src", "default-src"} {
		if sources, ok := policy[directive]; ok {
			return sources, true
		}
	}
	return nil, false
}

func evaluateCSP(urlValue string, enforced, reportOnly []string) []Finding {
	var findings []Finding
	for _, value := range reportOnly {
		if _, err := parseCSP(value); err != nil {
			findings = append(findings, finding("CSP_INVALID", "warning",
				fmt.Sprintf("%s returned an invalid report-only CSP: %v.", urlValue, err)))
		}
	}
	if len(enforced) == 0 {
		if len(reportOnly) > 0 {
			return append(findings, finding("CSP_NOT_ENFORCED", "warning",
				fmt.Sprintf("%s returned only Content-Security-Policy-Report-Only and no enforced CSP.", urlValue)))
		}
		return append(findings, finding("CSP_MISSING", "warning",
			fmt.Sprintf("%s is an HTML document without an enforced Content-Security-Policy.", urlValue)))
	}
	policies := make([]cspPolicy, 0, len(enforced))
	for _, value := range enforced {
		policy, err := parseCSP(value)
		if err != nil {
			findings = append(findings, finding("CSP_INVALID", "warning",
				fmt.Sprintf("%s returned an invalid enforced CSP: %v.", urlValue, err)))
			continue
		}
		policies = append(policies, policy)
	}
	if len(policies) == 0 {
		return findings
	}
	if allCSPPoliciesPermit(policies, "'unsafe-eval'") {
		findings = append(findings, finding("CSP_UNSAFE_EVAL", "warning",
			fmt.Sprintf("%s has an effective script policy that permits 'unsafe-eval'.", urlValue)))
	}
	if allCSPPoliciesPermitUnsafeInline(policies) {
		findings = append(findings, finding("CSP_UNSAFE_INLINE_SCRIPT", "warning",
			fmt.Sprintf("%s has an effective script policy where 'unsafe-inline' is not neutralized by a nonce or hash source.", urlValue)))
	}
	if allCSPPoliciesPermitWildcard(policies) {
		findings = append(findings, finding("CSP_WILDCARD_SCRIPT_SOURCE", "warning",
			fmt.Sprintf("%s has an effective script policy that permits the wildcard source *.", urlValue)))
	}
	return findings
}

func allCSPPoliciesPermitWildcard(policies []cspPolicy) bool {
	if len(policies) == 0 {
		return false
	}
	explicitWildcard := false
	for _, policy := range policies {
		sources, constrained := effectiveScriptSources(policy)
		if !constrained {
			continue
		}
		if !containsFold(sources, "*") {
			return false
		}
		explicitWildcard = true
	}
	return explicitWildcard
}

func allCSPPoliciesPermit(policies []cspPolicy, token string) bool {
	if len(policies) == 0 {
		return false
	}
	for _, policy := range policies {
		sources, constrained := effectiveScriptSources(policy)
		if constrained && !containsFold(sources, token) {
			return false
		}
	}
	return true
}

func allCSPPoliciesPermitUnsafeInline(policies []cspPolicy) bool {
	if len(policies) == 0 {
		return false
	}
	for _, policy := range policies {
		sources, constrained := effectiveScriptSources(policy)
		if constrained && (!containsFold(sources, "'unsafe-inline'") || hasCSPNonceOrHash(sources)) {
			return false
		}
	}
	return true
}

func hasCSPNonceOrHash(sources []string) bool {
	for _, source := range sources {
		if validCSPNonceOrHash(source) {
			return true
		}
	}
	return false
}

func validCSPNonceOrHash(source string) bool {
	if len(source) < 3 || source[0] != '\'' || source[len(source)-1] != '\'' {
		return false
	}
	value := source[1 : len(source)-1]
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "nonce-") {
		return validBase64Value(value[len("nonce-"):], 0)
	}
	for _, hash := range []struct {
		prefix string
		bytes  int
	}{{"sha256-", 32}, {"sha384-", 48}, {"sha512-", 64}} {
		if strings.HasPrefix(lower, hash.prefix) {
			return validBase64Value(value[len(hash.prefix):], hash.bytes)
		}
	}
	return false
}

func validBase64Value(value string, requiredBytes int) bool {
	if value == "" {
		return false
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) > 0 && (requiredBytes == 0 || len(decoded) == requiredBytes) {
			return true
		}
	}
	return false
}

func evaluateFraming(urlValue string, cspValues, xfoValues []string) []Finding {
	for _, value := range cspValues {
		policy, err := parseCSP(value)
		if err == nil {
			if sources, ok := policy["frame-ancestors"]; ok && len(sources) > 0 {
				return nil
			}
		}
	}
	if len(xfoValues) == 0 {
		return []Finding{finding("CLICKJACKING_PROTECTION_MISSING", "warning",
			fmt.Sprintf("%s has neither CSP frame-ancestors nor a valid X-Frame-Options policy.", urlValue))}
	}
	valid := ""
	for _, field := range xfoValues {
		for _, value := range strings.Split(field, ",") {
			value = strings.ToUpper(strings.TrimSpace(value))
			if value != "DENY" && value != "SAMEORIGIN" {
				return []Finding{finding("X_FRAME_OPTIONS_INVALID", "warning",
					fmt.Sprintf("%s returned malformed X-Frame-Options value %q.", urlValue, value))}
			}
			if valid != "" && valid != value {
				return []Finding{finding("X_FRAME_OPTIONS_INVALID", "warning",
					fmt.Sprintf("%s returned conflicting X-Frame-Options values %q and %q.", urlValue, valid, value))}
			}
			valid = value
		}
	}
	if valid == "" {
		return []Finding{finding("X_FRAME_OPTIONS_INVALID", "warning",
			fmt.Sprintf("%s returned an empty X-Frame-Options policy.", urlValue))}
	}
	return nil
}

var validReferrerPolicies = map[string]bool{
	"no-referrer": true, "no-referrer-when-downgrade": true, "origin": true,
	"origin-when-cross-origin": true, "same-origin": true, "strict-origin": true,
	"strict-origin-when-cross-origin": true, "unsafe-url": true,
}

func evaluateReferrerPolicy(urlValue string, values []string) []Finding {
	if len(values) == 0 {
		return []Finding{finding("REFERRER_POLICY_MISSING", "info",
			fmt.Sprintf("%s returned no Referrer-Policy header.", urlValue))}
	}
	selected := ""
	for _, field := range values {
		for _, token := range strings.Split(field, ",") {
			token = strings.ToLower(strings.TrimSpace(token))
			if validReferrerPolicies[token] {
				selected = token
			}
		}
	}
	if selected == "unsafe-url" {
		return []Finding{finding("REFERRER_POLICY_UNSAFE_URL", "warning",
			fmt.Sprintf("%s selected Referrer-Policy unsafe-url, which sends full referrers broadly.", urlValue))}
	}
	return nil
}

func evaluatePermissionsPolicy(urlValue string, values []string) []Finding {
	if len(values) == 0 {
		return []Finding{finding("PERMISSIONS_POLICY_MISSING", "info",
			fmt.Sprintf("%s returned no Permissions-Policy header.", urlValue))}
	}
	sensitive := map[string]bool{"camera": true, "microphone": true, "geolocation": true, "payment": true, "usb": true}
	var wildcard []string
	for _, field := range values {
		for _, raw := range splitPermissionsDirectives(field) {
			name, allowlist, ok := strings.Cut(raw, "=")
			if !ok || !sensitive[strings.ToLower(strings.TrimSpace(name))] {
				continue
			}
			allowlist = strings.ReplaceAll(strings.TrimSpace(allowlist), " ", "")
			if allowlist == "*" || allowlist == "(*)" {
				wildcard = append(wildcard, strings.ToLower(strings.TrimSpace(name)))
			}
		}
	}
	if len(wildcard) > 0 {
		sort.Strings(wildcard)
		return []Finding{finding("PERMISSIONS_POLICY_SENSITIVE_WILDCARD", "warning",
			fmt.Sprintf("%s grants sensitive Permissions-Policy features to wildcard origins: %s.", urlValue, strings.Join(wildcard, ", ")))}
	}
	return nil
}

func observeSensitivePermissions(values []string) []PermissionObservation {
	sensitive := map[string]bool{"camera": true, "microphone": true, "geolocation": true, "payment": true, "usb": true}
	byFeature := make(map[string]PermissionObservation)
	for _, field := range values {
		for _, raw := range splitPermissionsDirectives(field) {
			name, allowlist, ok := strings.Cut(raw, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if !sensitive[name] {
				continue
			}
			observation := PermissionObservation{Feature: name, Valid: ok}
			if ok {
				allowlist = strings.TrimSpace(allowlist)
				if strings.HasPrefix(allowlist, "(") && strings.HasSuffix(allowlist, ")") {
					allowlist = strings.TrimSpace(allowlist[1 : len(allowlist)-1])
				}
				if allowlist != "" {
					observation.Allowlist = strings.Fields(allowlist)
				}
			}
			byFeature[name] = observation
		}
	}
	order := []string{"camera", "microphone", "geolocation", "payment", "usb"}
	var result []PermissionObservation
	for _, feature := range order {
		if observation, ok := byFeature[feature]; ok {
			result = append(result, observation)
		}
	}
	return result
}

func splitPermissionsDirectives(value string) []string {
	var result []string
	start, depth := 0, 0
	for index, r := range value {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				result = append(result, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	return append(result, strings.TrimSpace(value[start:]))
}

func headerHasToken(values []string, wanted string) bool {
	for _, field := range values {
		for _, token := range strings.Split(field, ",") {
			if strings.EqualFold(strings.TrimSpace(token), wanted) {
				return true
			}
		}
	}
	return false
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

var softwareVersionPattern = regexp.MustCompile(`(?i)(?:^|[/ ])v?\d+(?:\.\d+)+`)

func exposesSoftwareVersion(values []string) bool {
	for _, value := range values {
		if softwareVersionPattern.MatchString(value) {
			return true
		}
	}
	return false
}
