package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// AuthHandler provides the stub handler for OIDC authentication.
type AuthHandler struct {
	// Values in templates
	Issuer     string
	AuthCode   string
	IDToken    string
	PrivateKey struct{ N, E string }

	// Response templates
	discoveryJSON *template.Template
	tokenJSON     *template.Template
	jwksJSON      *template.Template
}

// NewAuthHandler returns a new AuthHandler.
func NewAuthHandler(t *testing.T, issuer string) *AuthHandler {
	h := &AuthHandler{
		Issuer:        issuer,
		AuthCode:      "0b70006b-f62a-4438-aba5-c0b96775d8e5",
		discoveryJSON: template.Must(template.ParseFiles("testdata/oidc-discovery.json")),
		tokenJSON:     template.Must(template.ParseFiles("testdata/oidc-token.json")),
		jwksJSON:      template.Must(template.ParseFiles("testdata/oidc-jwks.json")),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Issuer:    h.Issuer,
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
	return h
}

func (s *AuthHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	m := r.Method
	p := r.URL.Path
	log.Printf("[auth-server] %s %s", m, r.RequestURI)
	switch {
	case m == "GET" && p == "/.well-known/openid-configuration":
		w.Header().Add("Content-Type", "application/json")
		if err := s.discoveryJSON.Execute(w, s); err != nil {
			return err
		}
	case m == "GET" && p == "/protocol/openid-connect/auth":
		// Authentication Response
		// http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
		q := r.URL.Query()
		to := fmt.Sprintf("%s?state=%s&code=%s", q.Get("redirect_uri"), q.Get("state"), s.AuthCode)
		http.Redirect(w, r, to, 302)
	case m == "POST" && p == "/protocol/openid-connect/token":
		// Token Response
		// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
		if err := r.ParseForm(); err != nil {
			return err
		}
		if s.AuthCode != r.Form.Get("code") {
			return fmt.Errorf("code wants %s but %s", s.AuthCode, r.Form.Get("code"))
		}
		w.Header().Add("Content-Type", "application/json")
		if err := s.tokenJSON.Execute(w, s); err != nil {
			return err
		}
	case m == "GET" && p == "/protocol/openid-connect/certs":
		w.Header().Add("Content-Type", "application/json")
		if err := s.jwksJSON.Execute(w, s); err != nil {
			return err
		}
	default:
		http.Error(w, "Not Found", 404)
	}
	return nil
}

func (s *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := s.serveHTTP(w, r); err != nil {
		log.Printf("[auth-server] Error: %s", err)
		w.WriteHeader(500)
	}
}
