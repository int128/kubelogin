// Package idp provides a test double of the identity provider of OpenID Connect.
package idp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"golang.org/x/xerrors"
)

func NewHandler(t *testing.T, service Service) *Handler {
	return &Handler{t, service}
}

type Handler struct {
	t       *testing.T
	service Service
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.serveHTTP(w, r)
	if err == nil {
		return
	}
	if errResp := new(ErrorResponse); xerrors.As(err, &errResp) {
		h.t.Logf("idp/handler: 400 Bad Request: %+v", errResp)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(400)
		e := json.NewEncoder(w)
		if err := e.Encode(errResp); err != nil {
			h.t.Errorf("idp/handler: could not write the response: %s", err)
		}
		return
	}
	h.t.Errorf("idp/handler: 500 Server Error: %s", err)
	http.Error(w, err.Error(), 500)
}

func (h *Handler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	m := r.Method
	p := r.URL.Path
	h.t.Logf("idp/handler: %s %s", m, r.RequestURI)
	switch {
	case m == "GET" && p == "/.well-known/openid-configuration":
		discoveryResponse := h.service.Discovery()
		w.Header().Add("Content-Type", "application/json")
		e := json.NewEncoder(w)
		if err := e.Encode(discoveryResponse); err != nil {
			return xerrors.Errorf("could not render json: %w", err)
		}
	case m == "GET" && p == "/certs":
		certificatesResponse := h.service.GetCertificates()
		w.Header().Add("Content-Type", "application/json")
		e := json.NewEncoder(w)
		if err := e.Encode(certificatesResponse); err != nil {
			return xerrors.Errorf("could not render json: %w", err)
		}
	case m == "GET" && p == "/auth":
		// Authentication Response
		// http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
		q := r.URL.Query()
		redirectURI, scope, state := q.Get("redirect_uri"), q.Get("scope"), q.Get("state")
		code, err := h.service.AuthenticateCode(scope)
		if err != nil {
			return xerrors.Errorf("authentication error: %w", err)
		}
		to := fmt.Sprintf("%s?state=%s&code=%s", redirectURI, state, code)
		http.Redirect(w, r, to, 302)
	case m == "POST" && p == "/token":
		if err := r.ParseForm(); err != nil {
			return xerrors.Errorf("could not parse the form: %w", err)
		}
		grantType := r.Form.Get("grant_type")
		switch grantType {
		case "authorization_code":
			// 3.1.3.1. Token Request
			// 3.1.3.3. Successful Token Response
			// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
			code := r.Form.Get("code")
			tokenResponse, err := h.service.Exchange(code)
			if err != nil {
				return xerrors.Errorf("token request error: %w", err)
			}
			w.Header().Add("Content-Type", "application/json")
			e := json.NewEncoder(w)
			if err := e.Encode(tokenResponse); err != nil {
				return xerrors.Errorf("could not render json: %w", err)
			}
		case "password":
			// Token Response
			// https://tools.ietf.org/html/rfc6749#section-4.3
			username, password, scope := r.Form.Get("username"), r.Form.Get("password"), r.Form.Get("scope")
			tokenResponse, err := h.service.AuthenticatePassword(username, password, scope)
			if err != nil {
				return xerrors.Errorf("authentication error: %w", err)
			}
			w.Header().Add("Content-Type", "application/json")
			e := json.NewEncoder(w)
			if err := e.Encode(tokenResponse); err != nil {
				return xerrors.Errorf("could not render json: %w", err)
			}
		case "refresh_token":
			// 12.1. Refresh Request
			// 12.2. Successful Refresh Response
			// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
			refreshToken := r.Form.Get("refresh_token")
			tokenResponse, err := h.service.Refresh(refreshToken)
			if err != nil {
				return xerrors.Errorf("token refresh error: %w", err)
			}
			w.Header().Add("Content-Type", "application/json")
			e := json.NewEncoder(w)
			if err := e.Encode(tokenResponse); err != nil {
				return xerrors.Errorf("could not render json: %w", err)
			}
		default:
			return xerrors.Errorf("invalid grant_type: %s", grantType)
		}
	default:
		http.NotFound(w, r)
	}
	return nil
}
