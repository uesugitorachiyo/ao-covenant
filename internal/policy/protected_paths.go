package policy

import (
	"path"
	"strings"
)

func containsNormalized(values []string, resource string) bool {
	for _, value := range values {
		if normalizeResource(value) == resource {
			return true
		}
	}
	return false
}

func normalizeResource(raw string) string {
	return path.Clean(strings.ReplaceAll(raw, "\\", "/"))
}
