// Package handler provides a HTTP handler for the OpenID Connect Provider.
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func New(t *testing.T, provider Provider) *Handler {
	return &Handler{t, provider}
}

// Handler provides a HTTP handler for the OpenID Connect Provider.
// You need to implement the Provider interface.
// Note that this skips some security checks and is only for testing.
type Handler struct {
	t        *testing.T
	provider Provider
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wr := &responseWriterRecorder{w, 200}
	err := h.serveHTTP(wr, r)
	if err == nil {
		h.t.Logf("%d %s %s", wr.statusCode, r.Method, r.RequestURI)
		return
	}
	if errResp := new(ErrorResponse); errors.As(err, &errResp) {
		h.t.Logf("400 %s %s: %s", r.Method, r.RequestURI, err)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(400)
		e := json.NewEncoder(w)
		if err := e.Encode(errResp); err != nil {
			h.t.Errorf("idp/handler: could not write the response: %s", err)
		}
		return
	}
	h.t.Logf("500 %s %s: %s", r.Method, r.RequestURI, err)
	http.Error(w, err.Error(), 500)
}

type responseWriterRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterRecorder) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
	w.statusCode = statusCode
}

func (h *Handler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	m := r.Method
	p := r.URL.Path
	switch {
	case m == "GET" && p == "/.well-known/openid-configuration":
		discoveryResponse := h.provider.Discovery()
		w.Header().Add("Content-Type", "application/json")
		e := json.NewEncoder(w)
		if err := e.Encode(discoveryResponse); err != nil {
			return fmt.Errorf("could not render json: %w", err)
		}
	case m == "GET" && p == "/certs":
		certificatesResponse := h.provider.GetCertificates()
		w.Header().Add("Content-Type", "application/json")
		e := json.NewEncoder(w)
		if err := e.Encode(certificatesResponse); err != nil {
			return fmt.Errorf("could not render json: %w", err)
		}
	case m == "GET" && p == "/auth":
		q := r.URL.Query()
		redirectURI, state := q.Get("redirect_uri"), q.Get("state")
		code, err := h.provider.AuthenticateCode(AuthenticationRequest{
			RedirectURI:         redirectURI,
			State:               state,
			Scope:               q.Get("scope"),
			Nonce:               q.Get("nonce"),
			CodeChallenge:       q.Get("code_challenge"),
			CodeChallengeMethod: q.Get("code_challenge_method"),
			RawQuery:            q,
		})
		if err != nil {
			return fmt.Errorf("authentication error: %w", err)
		}
		to := fmt.Sprintf("%s?state=%s&code=%s", redirectURI, state, code)
		http.Redirect(w, r, to, 302)
	case m == "POST" && p == "/token":
		if err := r.ParseForm(); err != nil {
			return fmt.Errorf("could not parse the form: %w", err)
		}
		grantType := r.Form.Get("grant_type")
		switch grantType {
		case "authorization_code":
			tokenResponse, err := h.provider.Exchange(TokenRequest{
				Code:         r.Form.Get("code"),
				CodeVerifier: r.Form.Get("code_verifier"),
			})
			if err != nil {
				return fmt.Errorf("token request error: %w", err)
			}
			w.Header().Add("Content-Type", "application/json")
			e := json.NewEncoder(w)
			if err := e.Encode(tokenResponse); err != nil {
				return fmt.Errorf("could not render json: %w", err)
			}
		case "password":
			// 4.3. Resource Owner Password Credentials Grant
			// https://tools.ietf.org/html/rfc6749#section-4.3
			username, password, scope := r.Form.Get("username"), r.Form.Get("password"), r.Form.Get("scope")
			tokenResponse, err := h.provider.AuthenticatePassword(username, password, scope)
			if err != nil {
				return fmt.Errorf("authentication error: %w", err)
			}
			w.Header().Add("Content-Type", "application/json")
			e := json.NewEncoder(w)
			if err := e.Encode(tokenResponse); err != nil {
				return fmt.Errorf("could not render json: %w", err)
			}
		case "refresh_token":
			// 12.1. Refresh Request
			// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
			refreshToken := r.Form.Get("refresh_token")
			tokenResponse, err := h.provider.Refresh(refreshToken)
			if err != nil {
				return fmt.Errorf("token refresh error: %w", err)
			}
			w.Header().Add("Content-Type", "application/json")
			e := json.NewEncoder(w)
			if err := e.Encode(tokenResponse); err != nil {
				return fmt.Errorf("could not render json: %w", err)
			}
		default:
			// 5.2. Error Response
			// https://tools.ietf.org/html/rfc6749#section-5.2
			return &ErrorResponse{
				Code:        "invalid_grant",
				Description: fmt.Sprintf("unknown grant_type %s", grantType),
			}
		}
	default:
		http.NotFound(w, r)
	}
	return nil
}
