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
	Issuer         string
	Scope          string
	IDToken        string
	RefreshToken   string
	IDTokenKeyPair *rsa.PrivateKey
	Code           string
}

type codeHandler struct {
	t         *testing.T
	c         CodeConfig
	templates templates
	values    templateValues
}

func NewCodeHandler(t *testing.T, c CodeConfig) *codeHandler {
	if c.Scope == "" {
		c.Scope = "openid"
	}
	if c.Code == "" {
		c.Code = "3d24a8bd-35e6-457d-999e-e04bb1dfcec7"
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
		h.t.Logf("authserver/codeHandler: Error: %s", err)
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
	case m == "GET" && p == "/protocol/openid-connect/auth":
		// Authentication Response
		// http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
		q := r.URL.Query()
		if h.c.Scope != q.Get("scope") {
			return xerrors.Errorf("scope wants %s but %s", h.c.Scope, q.Get("scope"))
		}
		to := fmt.Sprintf("%s?state=%s&code=%s", q.Get("redirect_uri"), q.Get("state"), h.c.Code)
		http.Redirect(w, r, to, 302)
	case m == "POST" && p == "/protocol/openid-connect/token":
		// Token Response
		// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
		if err := r.ParseForm(); err != nil {
			return xerrors.Errorf("could not parse the form: %w", err)
		}
		grantType, code := r.Form.Get("grant_type"), r.Form.Get("code")
		if grantType != "authorization_code" {
			return xerrors.Errorf("grant_type wants authorization_code but %s", grantType)
		}
		if h.c.Code != code {
			return xerrors.Errorf("code wants %s but %s", h.c.Code, code)
		}
		w.Header().Add("Content-Type", "application/json")
		if err := h.templates.token.Execute(w, h.values); err != nil {
			return xerrors.Errorf("could not execute the template: %w", err)
		}
	case m == "GET" && p == "/protocol/openid-connect/certs":
		w.Header().Add("Content-Type", "application/json")
		if err := h.templates.jwks.Execute(w, h.values); err != nil {
			return xerrors.Errorf("could not execute the template: %w", err)
		}
	default:
		http.Error(w, "Not Found", 404)
	}
	return nil
}
