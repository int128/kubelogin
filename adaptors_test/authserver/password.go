package authserver

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"testing"

	"github.com/pkg/errors"
)

// PasswordConfig represents a config for Resource Owner Password Credentials Grant.
type PasswordConfig struct {
	Issuer         string
	Scope          string
	IDToken        string
	RefreshToken   string
	IDTokenKeyPair *rsa.PrivateKey
	Username       string
	Password       string
}

type passwordHandler struct {
	t         *testing.T
	c         PasswordConfig
	templates templates
	values    templateValues
}

func NewPasswordHandler(t *testing.T, c PasswordConfig) *passwordHandler {
	if c.Scope == "" {
		c.Scope = "openid"
	}
	h := passwordHandler{
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

func (h *passwordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.serveHTTP(w, r); err != nil {
		h.t.Logf("authserver/passwordHandler: Error: %s", err)
		w.WriteHeader(500)
	}
}

func (h *passwordHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	m := r.Method
	p := r.URL.Path
	h.t.Logf("authserver/passwordHandler: %s %s", m, r.RequestURI)
	switch {
	case m == "GET" && p == "/.well-known/openid-configuration":
		w.Header().Add("Content-Type", "application/json")
		if err := h.templates.discovery.Execute(w, h.values); err != nil {
			return errors.Wrapf(err, "could not execute the template")
		}
	case m == "POST" && p == "/protocol/openid-connect/token":
		// Token Response
		// https://tools.ietf.org/html/rfc6749#section-4.3
		if err := r.ParseForm(); err != nil {
			return errors.Wrapf(err, "could not parse the form")
		}
		grantType, username, password := r.Form.Get("grant_type"), r.Form.Get("username"), r.Form.Get("password")
		if grantType != "password" {
			return errors.Errorf("grant_type wants password but %s", grantType)
		}
		if h.c.Username != username {
			return errors.Errorf("username wants %s but %s", h.c.Username, username)
		}
		if h.c.Password != password {
			return errors.Errorf("password wants %s but %s", h.c.Password, password)
		}
		w.Header().Add("Content-Type", "application/json")
		if err := h.templates.token.Execute(w, h.values); err != nil {
			return errors.Wrapf(err, "could not execute the template")
		}
	case m == "GET" && p == "/protocol/openid-connect/certs":
		w.Header().Add("Content-Type", "application/json")
		if err := h.templates.jwks.Execute(w, h.values); err != nil {
			return errors.Wrapf(err, "could not execute the template")
		}
	default:
		http.Error(w, "Not Found", 404)
	}
	return nil
}
