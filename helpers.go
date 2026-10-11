package main

import "strings"

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func joinErrors(first, second string) string {
	if first == "" {
		return second
	}
	return strings.Join([]string{first, second}, "; ")
}
