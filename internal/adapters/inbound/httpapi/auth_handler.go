package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/haribabuk113/iam/internal/application/auth"
	"github.com/haribabuk113/iam/internal/application/ports/outbound"
	"github.com/haribabuk113/iam/internal/domain/identity"
	"github.com/haribabuk113/iam/internal/domain/provider"
)

// AuthHandler exposes the login/callback/token-exchange endpoints (PRD
// §14, architecture plan §9). It owns only transport concerns — PKCE
// generation, state correlation, redirect validation — and delegates all
// identity resolution to auth.Service.
type AuthHandler struct {
	svc             *auth.Service
	states          *StateStore
	exchanges       *ExchangeStore
	redirectOrigins map[string][]string // app_id -> allowed return_to origins
	log             outbound.Logger
}

func NewAuthHandler(svc *auth.Service, states *StateStore, exchanges *ExchangeStore, redirectOrigins map[string][]string, log outbound.Logger) *AuthHandler {
	return &AuthHandler{svc: svc, states: states, exchanges: exchanges, redirectOrigins: redirectOrigins, log: log}
}

// Login starts the SSO flow: GET /login?provider=google&app_id=...&return_to=...
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	p := provider.Name(r.URL.Query().Get("provider"))
	appID := r.URL.Query().Get("app_id")
	returnTo := r.URL.Query().Get("return_to")

	if !p.Valid() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_provider"})
		return
	}
	if !originAllowed(returnTo, h.redirectOrigins[appID]) {
		h.log.Warn("return_to rejected", "app_id", appID, "return_to", returnTo, "allowed_for_app_id", h.redirectOrigins[appID])
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "return_to_not_allowed"})
		return
	}

	verifier, err := newPKCEVerifier()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	state, err := newState()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	authURL, err := h.svc.BeginLogin(p, state, pkceChallenge(verifier))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "begin_login_failed"})
		return
	}

	h.states.Put(state, loginState{
		CodeVerifier: verifier,
		Provider:     p,
		ReturnTo:     returnTo,
		AppID:        appID,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback lands the browser back from Supabase: GET /callback?code=...&iam_state=...
func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("iam_state")

	st, ok := h.states.Take(state)
	if !ok || code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_or_expired_state"})
		return
	}

	id, err := h.svc.CompleteLogin(r.Context(), code, st.CodeVerifier)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_failed"})
		return
	}

	exchangeCode, err := newExchangeCode()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	h.exchanges.Put(exchangeCode, string(id.ID))

	http.Redirect(w, r, st.ReturnTo+"?code="+exchangeCode, http.StatusFound)
}

type tokenRequest struct {
	Code string `json:"code"`
}

type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	EcosystemID string    `json:"ecosystem_id"`
}

// Token exchanges the opaque code handed to the application's redirect
// for the IAM's own JWT: POST /token {"code": "..."}. The application's
// backend calls this server-to-server — the code alone was never a
// bearer credential (architecture plan §9).
func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	ecosystemID, ok := h.exchanges.Take(req.Code)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_or_expired_code"})
		return
	}

	id, err := h.svc.IdentityByID(r.Context(), identity.ClientEcosystemID(ecosystemID))
	if err != nil || id == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "identity_not_found"})
		return
	}

	token, expiresAt, err := h.svc.IssueToken(*id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign_failed"})
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: token, ExpiresAt: expiresAt, EcosystemID: string(id.ID)})
}

type signUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

type signUpResponse struct {
	Status      string    `json:"status"` // "confirmation_required" | "ok"
	AccessToken string    `json:"access_token,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	EcosystemID string    `json:"ecosystem_id,omitempty"`
}

type signInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignUp registers a new email+password user: POST /signup
// {"email":"...","password":"...","full_name":"..."}. Unlike the OAuth
// flow, this is a direct API call with no browser redirect involved, so
// the JWT is returned straight in the response body — the opaque-code
// indirection in Callback exists only to keep tokens out of browser
// history/referrer/logs, which doesn't apply here.
//
// If the Supabase project requires email confirmation (the default),
// no token is issued yet — the response reports "confirmation_required"
// and the caller must sign in after the user confirms their email.
func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req signUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	id, sessionIssued, err := h.svc.SignUp(r.Context(), req.Email, req.Password, req.FullName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "signup_failed"})
		return
	}
	if !sessionIssued {
		writeJSON(w, http.StatusAccepted, signUpResponse{Status: "confirmation_required"})
		return
	}

	token, expiresAt, err := h.svc.IssueToken(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign_failed"})
		return
	}
	writeJSON(w, http.StatusOK, signUpResponse{Status: "ok", AccessToken: token, ExpiresAt: expiresAt, EcosystemID: string(id.ID)})
}

// SignIn authenticates an existing email+password user: POST /signin
// {"email":"...","password":"..."}.
func (h *AuthHandler) SignIn(w http.ResponseWriter, r *http.Request) {
	var req signInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	id, err := h.svc.SignIn(r.Context(), req.Email, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signin_failed"})
		return
	}

	token, expiresAt, err := h.svc.IssueToken(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign_failed"})
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: token, ExpiresAt: expiresAt, EcosystemID: string(id.ID)})
}
