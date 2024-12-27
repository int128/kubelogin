// Package handler provides HTTP handlers for the OpenID Connect Provider.
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/int128/kubelogin/integration_test/oidcserver/service"
)

func Register(t *testing.T, mux *http.ServeMux, provider service.Provider) {
	h := &Handlers{t, provider}
	mux.HandleFunc("GET /.well-known/openid-configuration", h.Discovery)
	mux.HandleFunc("GET /certs", h.GetCertificates)
	mux.HandleFunc("GET /auth", h.AuthenticateCode)
	mux.HandleFunc("POST /token", h.Exchange)
}

// Handlers provides HTTP handlers for the OpenID Connect Provider.
// You need to implement the Provider interface.
// Note that this skips some security checks and is only for testing.
type Handlers struct {
	t        *testing.T
	provider service.Provider
}

func (h *Handlers) handleError(w http.ResponseWriter, r *http.Request, f func() error) {
	wr := &responseWriterRecorder{w, 200}
	err := f()
	if err == nil {
		h.t.Logf("%d %s %s", wr.statusCode, r.Method, r.RequestURI)
		return
	}
	if errResp := new(service.ErrorResponse); errors.As(err, &errResp) {
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

func (h *Handlers) Discovery(w http.ResponseWriter, r *http.Request) {
	h.handleError(w, r, func() error {
		discoveryResponse := h.provider.Discovery()
		w.Header().Add("Content-Type", "application/json")
		e := json.NewEncoder(w)
		if err := e.Encode(discoveryResponse); err != nil {
			return fmt.Errorf("could not render json: %w", err)
		}
		return nil
	})
}

func (h *Handlers) GetCertificates(w http.ResponseWriter, r *http.Request) {
	h.handleError(w, r, func() error {
		certificatesResponse := h.provider.GetCertificates()
		w.Header().Add("Content-Type", "application/json")
		e := json.NewEncoder(w)
		if err := e.Encode(certificatesResponse); err != nil {
			return fmt.Errorf("could not render json: %w", err)
		}
		return nil
	})
}

func (h *Handlers) AuthenticateCode(w http.ResponseWriter, r *http.Request) {
	h.handleError(w, r, func() error {
		q := r.URL.Query()
		redirectURI, state := q.Get("redirect_uri"), q.Get("state")
		code, err := h.provider.AuthenticateCode(service.AuthenticationRequest{
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
		return nil
	})
}

func (h *Handlers) Exchange(w http.ResponseWriter, r *http.Request) {
	h.handleError(w, r, func() error {
		if err := r.ParseForm(); err != nil {
			return fmt.Errorf("could not parse the form: %w", err)
		}
		grantType := r.Form.Get("grant_type")
		switch grantType {
		case "authorization_code":
			tokenResponse, err := h.provider.Exchange(service.TokenRequest{
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
			return &service.ErrorResponse{
				Code:        "invalid_grant",
				Description: fmt.Sprintf("unknown grant_type %s", grantType),
			}
		}
		return nil
	})
}
