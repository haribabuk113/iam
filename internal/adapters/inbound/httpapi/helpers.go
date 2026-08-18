package httpapi

import "strings"

func originAllowed(returnTo string, allowed []string) bool {
	for _, o := range allowed {
		if strings.HasPrefix(returnTo, o) {
			return true
		}
	}
	return false
}
