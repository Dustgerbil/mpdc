package main

import (
	"fmt"
	"mime"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

func (scanner *httpScanner) inspectSecurityTXT(host string, allowedHosts map[string]bool) SecurityTXTResult {
	wellKnownURL := "https://" + host + "/.well-known/security.txt"
	page, body := scanner.fetchPage(wellKnownURL, host, allowedHosts,
		int64Limit(scanner.options.MaxBodyBytes, maxSecurityTXTBodyBytes), false)
	result := parseSecurityTXTPage(page, body, scanner.now())
	if result.Present {
		return result
	}
	if page.StatusCode != 404 && page.StatusCode != 410 {
		if page.StatusCode != 0 && len(result.Findings) == 0 {
			result.Findings = append(result.Findings, finding("SECURITY_TXT_INVALID", "warning",
				fmt.Sprintf("%s returned HTTP status %d instead of a successful security.txt response.", wellKnownURL, page.StatusCode)))
		}
		return result
	}

	legacyURL := "https://" + host + "/security.txt"
	legacyPage, legacyBody := scanner.fetchPage(legacyURL, host, allowedHosts,
		int64Limit(scanner.options.MaxBodyBytes, maxSecurityTXTBodyBytes), false)
	legacy := parseSecurityTXTPage(legacyPage, legacyBody, scanner.now())
	if legacy.Present {
		legacy.Findings = append(legacy.Findings, finding("SECURITY_TXT_LEGACY_LOCATION", "info",
			fmt.Sprintf("%s published security.txt at the legacy /security.txt location; the authoritative RFC 9116 location %s was absent.", host, wellKnownURL)))
		legacy.Findings = deduplicateFindings(legacy.Findings)
		return legacy
	}
	if legacy.Error != "" {
		if result.Error == "" {
			result.Error = legacy.Error
		} else {
			result.Error += "; " + legacy.Error
		}
	}
	result.Findings = append(result.Findings, finding("SECURITY_TXT_MISSING", "info",
		fmt.Sprintf("%s returned no security.txt at the authoritative %s location.", host, wellKnownURL)))
	result.Findings = deduplicateFindings(result.Findings)
	return result
}

func parseSecurityTXTPage(page HTTPPageResult, body []byte, now time.Time) SecurityTXTResult {
	result := SecurityTXTResult{
		RequestedURL: page.RequestedURL,
		FinalURL:     page.FinalURL,
		StatusCode:   page.StatusCode,
		ContentType:  page.ContentType,
		UTF8Valid:    utf8.Valid(body),
		Error:        page.Error,
	}
	result.Findings = append(result.Findings, securityTXTRedirectFindings(page)...)
	if page.StatusCode < 200 || page.StatusCode >= 300 {
		return result
	}
	result.Present = true
	var invalidReasons []string
	mediaType, _, err := mime.ParseMediaType(page.ContentType)
	if err != nil || !strings.EqualFold(mediaType, "text/plain") {
		invalidReasons = append(invalidReasons, fmt.Sprintf("Content-Type was %q instead of text/plain", page.ContentType))
	}
	if page.BodyTruncated {
		invalidReasons = append(invalidReasons, fmt.Sprintf("content exceeded the %d-byte security.txt limit", maxSecurityTXTBodyBytes))
	}
	if !result.UTF8Valid {
		invalidReasons = append(invalidReasons, "content was not valid UTF-8")
		result.Findings = append(result.Findings, finding("SECURITY_TXT_INVALID", "warning",
			fmt.Sprintf("%s returned security.txt content that is not valid UTF-8.", page.FinalURL)))
		return result
	}

	text := strings.TrimPrefix(string(body), "\ufeff")
	result.Signed = strings.Contains(text, "-----BEGIN PGP SIGNED MESSAGE-----") &&
		strings.Contains(text, "-----BEGIN PGP SIGNATURE-----")
	if result.Signed {
		text = signedSecurityTXTPayload(text)
	}
	unknown := make(map[string]bool)
	expiresSeen := false
	expiresValid := false
	expiresCount := 0
	for lineNumber, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-----") || strings.HasPrefix(line, "Hash:") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			invalidReasons = append(invalidReasons, fmt.Sprintf("line %d was not a non-empty field", lineNumber+1))
			continue
		}
		switch strings.ToLower(name) {
		case "contact":
			if validSecurityTXTURI(value) {
				result.Contacts = append(result.Contacts, value)
			} else {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Contact value %q was not an absolute URI", value))
			}
		case "expires":
			expiresSeen = true
			expiresCount++
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Expires value %q was not RFC3339", value))
			} else {
				result.Expires = &parsed
				expiresValid = true
			}
		case "canonical":
			if validSecurityTXTURI(value) {
				result.Canonical = append(result.Canonical, value)
			} else {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Canonical value %q was not an absolute URI", value))
			}
		case "policy":
			if validSecurityTXTURI(value) {
				result.Policy = append(result.Policy, value)
			} else {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Policy value %q was not an absolute URI", value))
			}
		case "encryption":
			if validSecurityTXTURI(value) {
				result.Encryption = append(result.Encryption, value)
			} else {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Encryption value %q was not an absolute URI", value))
			}
		case "preferred-languages":
			for _, language := range strings.Split(value, ",") {
				language = strings.TrimSpace(language)
				if language != "" {
					result.PreferredLanguages = append(result.PreferredLanguages, language)
				}
			}
		case "acknowledgments", "hiring":
			if !validSecurityTXTURI(value) {
				invalidReasons = append(invalidReasons, fmt.Sprintf("%s value %q was not an absolute URI", name, value))
			}
		default:
			unknown[name] = true
		}
	}
	if len(result.Contacts) == 0 {
		invalidReasons = append(invalidReasons, "no valid Contact field was present")
	}
	if expiresCount > 1 {
		invalidReasons = append(invalidReasons, fmt.Sprintf("%d Expires fields were present", expiresCount))
	}
	if !expiresSeen || !expiresValid {
		invalidReasons = append(invalidReasons, "no syntactically valid Expires field was present")
	} else if !result.Expires.After(now) {
		result.Findings = append(result.Findings, finding("SECURITY_TXT_EXPIRED", "warning",
			fmt.Sprintf("%s security.txt expired at %s.", page.FinalURL, result.Expires.Format(time.RFC3339))))
	}
	for name := range unknown {
		result.UnknownFieldNames = append(result.UnknownFieldNames, name)
	}
	sort.Strings(result.UnknownFieldNames)
	if len(invalidReasons) > 0 {
		result.Findings = append(result.Findings, finding("SECURITY_TXT_INVALID", "warning",
			fmt.Sprintf("%s returned malformed security.txt: %s.", page.FinalURL, strings.Join(invalidReasons, "; "))))
	}
	result.Findings = deduplicateFindings(result.Findings)
	return result
}

func signedSecurityTXTPayload(value string) string {
	start := strings.Index(value, "-----BEGIN PGP SIGNED MESSAGE-----")
	if start < 0 {
		return value
	}
	payload := value[start+len("-----BEGIN PGP SIGNED MESSAGE-----"):]
	if separator := strings.Index(payload, "\r\n\r\n"); separator >= 0 {
		payload = payload[separator+4:]
	} else if separator := strings.Index(payload, "\n\n"); separator >= 0 {
		payload = payload[separator+2:]
	}
	if end := strings.Index(payload, "-----BEGIN PGP SIGNATURE-----"); end >= 0 {
		payload = payload[:end]
	}
	lines := strings.Split(payload, "\n")
	for index := range lines {
		lines[index] = strings.TrimPrefix(lines[index], "- ")
	}
	return strings.Join(lines, "\n")
}

func securityTXTRedirectFindings(page HTTPPageResult) []Finding {
	var findings []Finding
	for _, item := range page.Findings {
		switch item.Code {
		case "HTTP_REDIRECT_TO_INSECURE":
			findings = append(findings, item)
			findings = append(findings, finding("SECURITY_TXT_INSECURE_REDIRECT", "warning",
				fmt.Sprintf("%s redirected security.txt toward cleartext URL %s.", itemURL(page), redirectTarget(page.RedirectChain))))
		default:
			findings = append(findings, item)
		}
	}
	return findings
}

func itemURL(page HTTPPageResult) string {
	if page.FinalURL != "" {
		return page.FinalURL
	}
	return page.RequestedURL
}

func redirectTarget(chain []RedirectHop) string {
	if len(chain) == 0 {
		return "an unknown URL"
	}
	return chain[len(chain)-1].ResolvedURL
}

func validSecurityTXTURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Scheme != "" && parsed.Fragment == ""
}
