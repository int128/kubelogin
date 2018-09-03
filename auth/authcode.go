package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

type authCodeFlow struct {
	Config          *oauth2.Config
	AuthCodeOptions []oauth2.AuthCodeOption
	ServerPort      int  // HTTP server port
	SkipOpenBrowser bool // skip opening browser if true
}

func (f *authCodeFlow) getToken(ctx context.Context) (*oauth2.Token, error) {
	code, err := f.getAuthCode(ctx)
	if err != nil {
		return nil, fmt.Errorf("Could not get an auth code: %s", err)
	}
	token, err := f.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("Could not exchange token: %s", err)
	}
	return token, nil
}

func (f *authCodeFlow) getAuthCode(ctx context.Context) (string, error) {
	state, err := generateState()
	if err != nil {
		return "", fmt.Errorf("Could not generate state parameter: %s", err)
	}
	codeCh := make(chan string)
	defer close(codeCh)
	errCh := make(chan error)
	defer close(errCh)
	server := http.Server{
		Addr: fmt.Sprintf("localhost:%d", f.ServerPort),
		Handler: &authCodeHandler{
			authCodeURL: f.Config.AuthCodeURL(state, f.AuthCodeOptions...),
			gotCode: func(code string, gotState string) {
				if gotState == state {
					codeCh <- code
				} else {
					errCh <- fmt.Errorf("State does not match, wants %s but %s", state, gotState)
				}
			},
			gotError: func(err error) {
				errCh <- err
			},
		},
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	go func() {
		log.Printf("Open http://localhost:%d for authorization", f.ServerPort)
		if !f.SkipOpenBrowser {
			time.Sleep(500 * time.Millisecond)
			browser.OpenURL(fmt.Sprintf("http://localhost:%d/", f.ServerPort))
		}
	}()
	select {
	case err := <-errCh:
		server.Shutdown(ctx)
		return "", err
	case code := <-codeCh:
		server.Shutdown(ctx)
		return code, nil
	case <-ctx.Done():
		server.Shutdown(ctx)
		return "", ctx.Err()
	}
}

type authCodeHandler struct {
	authCodeURL string
	gotCode     func(code string, state string)
	gotError    func(err error)
}

func (h *authCodeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.RequestURI)
	m := r.Method
	p := r.URL.Path
	q := r.URL.Query()
	switch {
	case m == "GET" && p == "/" && q.Get("error") != "":
		h.gotError(fmt.Errorf("OAuth Error: %s %s", q.Get("error"), q.Get("error_description")))
		http.Error(w, "OAuth Error", 500)

	case m == "GET" && p == "/" && q.Get("code") != "":
		h.gotCode(q.Get("code"), q.Get("state"))
		w.Header().Add("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>OK<script>window.close()</script></body></html>`)

	case m == "GET" && p == "/":
		http.Redirect(w, r, h.authCodeURL, 302)

	default:
		http.Error(w, "Not Found", 404)
	}
}
