package httpapi

import "net/url"

// originAllowed checks returnTo's scheme+host against an exact-match
// allow-list. Deliberately not a prefix check: strings.HasPrefix(returnTo,
// "http://localhost:3000") also matches "http://localhost:3000.evil.com",
// since HasPrefix has no notion of a URL's authority boundary. Parsing
// returnTo and comparing scheme+host closes that off.
func originAllowed(returnTo string, allowed []string) bool {
	u, err := url.Parse(returnTo)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	for _, o := range allowed {
		if origin == o {
			return true
		}
	}
	return false
}
