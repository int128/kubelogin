package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
)

// ReceiveAuthCodeFromWebBrowser starts a server and receives an auth code
func ReceiveAuthCodeFromWebBrowser(ctx context.Context, authCodeURL string, state string, authCodeCh chan<- string, errCh chan<- error) {
	server := http.Server{
		Addr: ":8000",
		Handler: &AuthCodeGrantHandler{
			AuthCodeURL: authCodeURL,
			State:       state,
			Resolve:     func(authCode string) { authCodeCh <- authCode },
			Reject:      func(err error) { errCh <- err },
		},
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		server.Shutdown(context.Background())
	}
}

// AuthCodeGrantHandler handles requests for OIDC auth code grant
type AuthCodeGrantHandler struct {
	AuthCodeURL string
	State       string
	Resolve     func(string)
	Reject      func(error)
}

func (s *AuthCodeGrantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.RequestURI)
	switch r.URL.Path {
	case "/":
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		errorCode := r.URL.Query().Get("error")
		errorDescription := r.URL.Query().Get("error_description")
		switch {
		case code != "" && state == s.State:
			s.Resolve(code)
			fmt.Fprintf(w, "Please back to the command line.")

		case code != "" && state != s.State:
			s.Reject(fmt.Errorf("OIDC state did not match. expected=%s, actual=%s", s.State, state))
			fmt.Fprintf(w, "Please back to the command line.")

		case errorCode != "":
			s.Reject(fmt.Errorf("OIDC error: %s %s", errorCode, errorDescription))
			fmt.Fprintf(w, "Please back to the command line.")

		default:
			http.Redirect(w, r, s.AuthCodeURL, 302)
		}

	default:
		http.Error(w, "Not Found", 404)
	}
}
