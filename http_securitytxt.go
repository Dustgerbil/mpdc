package main

import (
	"context"
	"fmt"
	"mime"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

func (scanner *httpScanner) inspectSecurityTXT(ctx context.Context, host string, allowedHosts map[string]bool) SecurityTXTResult {
	wellKnownURL := "https://" + host + "/.well-known/security.txt"
	page, body := scanner.fetchPage(ctx, wellKnownURL, host, allowedHosts,
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
	legacyPage, legacyBody := scanner.fetchPage(ctx, legacyURL, host, allowedHosts,
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
	canonicalCount := 0
	var canonicalRaw []string
	preferredLanguagesCount := 0
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
			if err := validateSecurityTXTURI("Contact", value); err == nil {
				result.Contacts = append(result.Contacts, redactURLForOutput(value))
			} else {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Contact value %q was invalid: %v", redactURLForOutput(value), err))
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
			canonicalCount++
			if err := validateSecurityTXTURI("Canonical", value); err == nil {
				result.Canonical = append(result.Canonical, redactURLForOutput(value))
				canonicalRaw = append(canonicalRaw, value)
			} else {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Canonical value %q was invalid: %v", redactURLForOutput(value), err))
			}
		case "policy":
			if err := validateSecurityTXTURI("Policy", value); err == nil {
				result.Policy = append(result.Policy, redactURLForOutput(value))
			} else {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Policy value %q was invalid: %v", redactURLForOutput(value), err))
			}
		case "encryption":
			if err := validateSecurityTXTURI("Encryption", value); err == nil {
				result.Encryption = append(result.Encryption, redactURLForOutput(value))
			} else {
				invalidReasons = append(invalidReasons, fmt.Sprintf("Encryption value %q was invalid: %v", redactURLForOutput(value), err))
			}
		case "preferred-languages":
			preferredLanguagesCount++
			for _, language := range strings.Split(value, ",") {
				language = strings.TrimSpace(language)
				if validLanguageTag(language) {
					result.PreferredLanguages = append(result.PreferredLanguages, language)
				} else {
					invalidReasons = append(invalidReasons, fmt.Sprintf("Preferred-Languages tag %q was not a valid RFC 5646 language tag", language))
				}
			}
		case "acknowledgments", "hiring":
			if err := validateSecurityTXTURI(name, value); err != nil {
				invalidReasons = append(invalidReasons, fmt.Sprintf("%s value %q was invalid: %v", name, redactURLForOutput(value), err))
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
	if canonicalCount > 0 && !canonicalContainsRetrievalURI(canonicalRaw, securityTXTRetrievalURL(page)) {
		invalidReasons = append(invalidReasons, fmt.Sprintf("retrieval URI %q was absent from Canonical fields", page.FinalURL))
	}
	if preferredLanguagesCount > 1 {
		invalidReasons = append(invalidReasons, fmt.Sprintf("%d Preferred-Languages fields were present", preferredLanguagesCount))
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

func validateSecurityTXTURI(field, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" {
		return fmt.Errorf("not an absolute URI")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("fragments are not permitted")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "http" {
		return fmt.Errorf("web URIs must use HTTPS")
	}
	if scheme == "https" && parsed.Hostname() == "" {
		return fmt.Errorf("HTTPS URI has no hostname")
	}
	switch strings.ToLower(field) {
	case "canonical", "policy", "acknowledgments", "hiring":
		if scheme != "https" {
			return fmt.Errorf("%s must use an HTTPS URI", field)
		}
	}
	return nil
}

func securityTXTRetrievalURL(page HTTPPageResult) string {
	if page.finalURLRaw != "" {
		return page.finalURLRaw
	}
	return page.FinalURL
}

func canonicalContainsRetrievalURI(values []string, retrieval string) bool {
	retrievalURL, err := url.Parse(retrieval)
	if err != nil || retrievalURL.Scheme == "" || retrievalURL.Hostname() == "" {
		return false
	}
	want := canonicalURL(retrievalURL)
	for _, value := range values {
		candidate, err := url.Parse(value)
		if err == nil && canonicalURL(candidate) == want {
			return true
		}
	}
	return false
}

func validLanguageTag(value string) bool {
	if grandfatheredLanguageTags[strings.ToLower(value)] {
		return true
	}
	parts := strings.Split(value, "-")
	if len(parts) == 0 || parts[0] == "" {
		return false
	}
	if strings.EqualFold(parts[0], "x") {
		return len(parts) > 1 && allLanguageSubtags(parts[1:], 1, 8)
	}
	if !asciiLetters(parts[0], 2, 8) {
		return false
	}
	index := 1
	if len(parts[0]) <= 3 {
		for count := 0; count < 3 && index < len(parts) && asciiLetters(parts[index], 3, 3); count++ {
			index++
		}
	}
	if index < len(parts) && asciiLetters(parts[index], 4, 4) {
		index++
	}
	if index < len(parts) && (asciiLetters(parts[index], 2, 2) || asciiDigits(parts[index], 3, 3)) {
		index++
	}
	variants := make(map[string]bool)
	for index < len(parts) && (asciiAlphanumeric(parts[index], 5, 8) || len(parts[index]) == 4 && isASCIIDigit(parts[index][0]) && asciiAlphanumeric(parts[index], 4, 4)) {
		variant := strings.ToLower(parts[index])
		if variants[variant] {
			return false
		}
		variants[variant] = true
		index++
	}
	extensions := make(map[string]bool)
	for index < len(parts) && len(parts[index]) == 1 && asciiAlphanumeric(parts[index], 1, 1) && !strings.EqualFold(parts[index], "x") {
		singleton := strings.ToLower(parts[index])
		if extensions[singleton] {
			return false
		}
		extensions[singleton] = true
		index++
		start := index
		for index < len(parts) && asciiAlphanumeric(parts[index], 2, 8) {
			index++
		}
		if index == start {
			return false
		}
	}
	if index < len(parts) && strings.EqualFold(parts[index], "x") {
		index++
		return index < len(parts) && allLanguageSubtags(parts[index:], 1, 8)
	}
	return index == len(parts)
}

var grandfatheredLanguageTags = map[string]bool{
	"art-lojban": true, "cel-gaulish": true, "en-gb-oed": true,
	"i-ami": true, "i-bnn": true, "i-default": true, "i-enochian": true,
	"i-hak": true, "i-klingon": true, "i-lux": true, "i-mingo": true,
	"i-navajo": true, "i-pwn": true, "i-tao": true, "i-tay": true, "i-tsu": true,
	"no-bok": true, "no-nyn": true, "sgn-be-fr": true, "sgn-be-nl": true,
	"sgn-ch-de": true, "zh-guoyu": true, "zh-hakka": true, "zh-min": true,
	"zh-min-nan": true, "zh-xiang": true,
}

func allLanguageSubtags(parts []string, minimum, maximum int) bool {
	for _, part := range parts {
		if !asciiAlphanumeric(part, minimum, maximum) {
			return false
		}
	}
	return true
}

func asciiLetters(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if value[i] < 'A' || value[i] > 'Z' && value[i] < 'a' || value[i] > 'z' {
			return false
		}
	}
	return true
}

func asciiDigits(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if !isASCIIDigit(value[i]) {
			return false
		}
	}
	return true
}

func asciiAlphanumeric(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if !isASCIIDigit(value[i]) && (value[i] < 'A' || value[i] > 'Z' && value[i] < 'a' || value[i] > 'z') {
			return false
		}
	}
	return true
}

func isASCIIDigit(value byte) bool { return value >= '0' && value <= '9' }
