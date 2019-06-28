package authserver

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"testing"

	"golang.org/x/xerrors"
)

// CodeConfig represents a config for Authorization Code Grant.
type CodeConfig struct {
	Issuer               string          // issuer in the discovery and token response
	IDTokenKeyPair       *rsa.PrivateKey // JWKS for the discovery response
	IDToken              string          // ID token in the token response
	RefreshToken         string          // refresh token in the token response
	ExpectedScope        string          // expected scope
	ExpectedCode         string          // expected authorization code
	ExpectedRefreshToken string          // expected refresh token (only for refreshing token)
}

type codeHandler struct {
	t         *testing.T
	c         CodeConfig
	templates templates
	values    templateValues
}

func NewCodeHandler(t *testing.T, c CodeConfig) *codeHandler {
	if c.ExpectedScope == "" {
		c.ExpectedScope = "openid"
	}
	if c.ExpectedCode == "" {
		c.ExpectedCode = "3d24a8bd-35e6-457d-999e-e04bb1dfcec7"
	}
	h := codeHandler{
		t:         t,
		c:         c,
		templates: parseTemplates(t),
		values: templateValues{
			Issuer:       c.Issuer,
			IDToken:      c.IDToken,
			RefreshToken: c.RefreshToken,
		},
	}
	if c.IDTokenKeyPair != nil {
		h.values.PrivateKey.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(c.IDTokenKeyPair.E)).Bytes())
		h.values.PrivateKey.N = base64.RawURLEncoding.EncodeToString(c.IDTokenKeyPair.N.Bytes())
	}
	return &h
}

func (h *codeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.serveHTTP(w, r); err != nil {
		h.t.Errorf("authserver/codeHandler: Error: %s", err)
		w.WriteHeader(500)
	}
}

func (h *codeHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	m := r.Method
	p := r.URL.Path
	h.t.Logf("authserver/codeHandler: %s %s", m, r.RequestURI)
	switch {
	case m == "GET" && p == "/.well-known/openid-configuration":
		w.Header().Add("Content-Type", "application/json")
		if err := h.templates.discovery.Execute(w, h.values); err != nil {
			return xerrors.Errorf("could not execute the template: %w", err)
		}
	case m == "GET" && p == "/protocol/openid-connect/certs":
		w.Header().Add("Content-Type", "application/json")
		if err := h.templates.jwks.Execute(w, h.values); err != nil {
			return xerrors.Errorf("could not execute the template: %w", err)
		}
	case m == "GET" && p == "/protocol/openid-connect/auth":
		// Authentication Response
		// http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
		q := r.URL.Query()
		if h.c.ExpectedScope != q.Get("scope") {
			return xerrors.Errorf("scope wants %s but %s", h.c.ExpectedScope, q.Get("scope"))
		}
		to := fmt.Sprintf("%s?state=%s&code=%s", q.Get("redirect_uri"), q.Get("state"), h.c.ExpectedCode)
		http.Redirect(w, r, to, 302)
	case m == "POST" && p == "/protocol/openid-connect/token":
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
			if h.c.ExpectedCode != code {
				return xerrors.Errorf("code wants %s but %s", h.c.ExpectedCode, code)
			}
			w.Header().Add("Content-Type", "application/json")
			if err := h.templates.token.Execute(w, h.values); err != nil {
				return xerrors.Errorf("could not execute the template: %w", err)
			}
		case "refresh_token":
			// 12.1. Refresh Request
			// 12.2. Successful Refresh Response
			// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
			refreshToken := r.Form.Get("refresh_token")
			if h.c.ExpectedRefreshToken != refreshToken {
				return xerrors.Errorf("refresh_token wants %s but %s", h.c.ExpectedRefreshToken, refreshToken)
			}
			w.Header().Add("Content-Type", "application/json")
			if err := h.templates.token.Execute(w, h.values); err != nil {
				return xerrors.Errorf("could not execute the template: %w", err)
			}
		default:
			return xerrors.Errorf("invalid grant_type: %s", grantType)
		}
	default:
		http.Error(w, "Not Found", 404)
	}
	return nil
}
