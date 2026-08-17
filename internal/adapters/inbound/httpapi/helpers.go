package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

func originAllowed(returnTo string, allowed []string) bool {
	for _, o := range allowed {
		if strings.HasPrefix(returnTo, o) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
