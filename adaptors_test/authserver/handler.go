package authserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"testing"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type handler struct {
	discovery *template.Template
	token     *template.Template
	jwks      *template.Template
	authCode  string

	Issuer     string
	Scope      string // Default to openid
	IDToken    string
	PrivateKey struct{ N, E string }
}

func newHandler(t *testing.T, c *Config) *handler {
	h := handler{
		discovery: readTemplate(t, "oidc-discovery.json"),
		token:     readTemplate(t, "oidc-token.json"),
		jwks:      readTemplate(t, "oidc-jwks.json"),
		authCode:  "3d24a8bd-35e6-457d-999e-e04bb1dfcec7",
		Issuer:    c.Issuer,
		Scope:     c.Scope,
	}
	if h.Scope == "" {
		h.Scope = "openid"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Issuer:    c.Issuer,
		Audience:  "kubernetes",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Could not generate a key pair: %s", err)
	}
	h.IDToken, err = token.SignedString(k)
	if err != nil {
		t.Fatalf("Could not generate an ID token: %s", err)
	}
	h.PrivateKey.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	h.PrivateKey.N = base64.RawURLEncoding.EncodeToString(k.N.Bytes())
	return &h
}

func readTemplate(t *testing.T, name string) *template.Template {
	t.Helper()
	tpl, err := template.ParseFiles("authserver/testdata/" + name)
	if err != nil {
		t.Fatalf("Could not read template %s: %s", name, err)
	}
	return tpl
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.serveHTTP(w, r); err != nil {
		log.Printf("[auth-server] Error: %s", err)
		w.WriteHeader(500)
	}
}

func (h *handler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	m := r.Method
	p := r.URL.Path
	log.Printf("[auth-server] %s %s", m, r.RequestURI)
	switch {
	case m == "GET" && p == "/.well-known/openid-configuration":
		w.Header().Add("Content-Type", "application/json")
		if err := h.discovery.Execute(w, h); err != nil {
			return err
		}
	case m == "GET" && p == "/protocol/openid-connect/auth":
		// Authentication Response
		// http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
		q := r.URL.Query()
		if h.Scope != q.Get("scope") {
			return fmt.Errorf("scope wants %s but %s", h.Scope, q.Get("scope"))
		}
		to := fmt.Sprintf("%s?state=%s&code=%s", q.Get("redirect_uri"), q.Get("state"), h.authCode)
		http.Redirect(w, r, to, 302)
	case m == "POST" && p == "/protocol/openid-connect/token":
		// Token Response
		// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
		if err := r.ParseForm(); err != nil {
			return err
		}
		if h.authCode != r.Form.Get("code") {
			return fmt.Errorf("code wants %s but %s", h.authCode, r.Form.Get("code"))
		}
		w.Header().Add("Content-Type", "application/json")
		if err := h.token.Execute(w, h); err != nil {
			return err
		}
	case m == "GET" && p == "/protocol/openid-connect/certs":
		w.Header().Add("Content-Type", "application/json")
		if err := h.jwks.Execute(w, h); err != nil {
			return err
		}
	default:
		http.Error(w, "Not Found", 404)
	}
	return nil
}
