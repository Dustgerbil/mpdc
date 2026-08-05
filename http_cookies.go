package main

import (
	"fmt"
	"sort"
	"strings"
)

func observeCookies(fields []string) []CookieObservation {
	result := make([]CookieObservation, 0, len(fields))
	for _, field := range fields {
		parts := strings.Split(field, ";")
		name, _, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		observation := CookieObservation{
			Name:         name,
			HostPrefix:   strings.HasPrefix(name, "__Host-"),
			SecurePrefix: strings.HasPrefix(name, "__Secure-"),
		}
		for _, raw := range parts[1:] {
			attribute, value, hasValue := strings.Cut(strings.TrimSpace(raw), "=")
			attribute = strings.ToLower(strings.TrimSpace(attribute))
			if attribute == "" {
				continue
			}
			observation.AttributeNames = append(observation.AttributeNames, attribute)
			switch attribute {
			case "secure":
				observation.Secure = true
			case "httponly":
				observation.HTTPOnly = true
			case "partitioned":
				observation.Partitioned = true
			case "samesite":
				if hasValue {
					observation.SameSite = canonicalSameSite(value)
				}
			case "path":
				if hasValue {
					observation.Path = strings.TrimSpace(value)
				}
			case "domain":
				if hasValue {
					observation.Domain = strings.ToLower(strings.TrimSpace(value))
				}
			}
		}
		sort.Strings(observation.AttributeNames)
		observation.AttributeNames = deduplicateStrings(observation.AttributeNames)
		result = append(result, observation)
	}
	return result
}

func canonicalSameSite(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return "Strict"
	case "lax":
		return "Lax"
	case "none":
		return "None"
	default:
		return strings.TrimSpace(value)
	}
}

func evaluateCookieFindings(urlValue string, cookies []CookieObservation) []Finding {
	var findings []Finding
	for _, cookie := range cookies {
		if !cookie.Secure {
			findings = append(findings, finding("COOKIE_SECURE_MISSING", "warning",
				fmt.Sprintf("%s set cookie %q over HTTPS without the Secure attribute.", urlValue, cookie.Name)))
		}
		if !cookie.HTTPOnly {
			findings = append(findings, finding("COOKIE_HTTPONLY_MISSING", "info",
				fmt.Sprintf("%s set cookie %q without HttpOnly; the passive response does not establish whether JavaScript access is required.", urlValue, cookie.Name)))
		}
		if cookie.SameSite == "" {
			findings = append(findings, finding("COOKIE_SAMESITE_MISSING", "info",
				fmt.Sprintf("%s set cookie %q without SameSite; the passive response does not establish the cookie's sensitivity.", urlValue, cookie.Name)))
		}
		if strings.EqualFold(cookie.SameSite, "None") && !cookie.Secure {
			findings = append(findings, finding("COOKIE_SAMESITE_NONE_WITHOUT_SECURE", "warning",
				fmt.Sprintf("%s set cookie %q with SameSite=None but without Secure.", urlValue, cookie.Name)))
		}
		if cookie.HostPrefix && (!cookie.Secure || cookie.Path != "/" || cookie.Domain != "") {
			findings = append(findings, finding("COOKIE_PREFIX_INVALID", "warning",
				fmt.Sprintf("%s set __Host- cookie %q without the required Secure, Path=/, and no Domain combination.", urlValue, cookie.Name)))
		}
		if cookie.SecurePrefix && !cookie.Secure {
			findings = append(findings, finding("COOKIE_PREFIX_INVALID", "warning",
				fmt.Sprintf("%s set __Secure- cookie %q without the required Secure attribute.", urlValue, cookie.Name)))
		}
	}
	return findings
}
