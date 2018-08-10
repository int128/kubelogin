package authz

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

// BrowserAuthCodeFlow is a flow to get a token by browser interaction.
type BrowserAuthCodeFlow struct {
	oauth2.Config
	Port int // HTTP server port
}

// GetToken returns a token.
func (f *BrowserAuthCodeFlow) GetToken(ctx context.Context) (*oauth2.Token, error) {
	f.Config.RedirectURL = fmt.Sprintf("http://localhost:%d/", f.Port)
	state, err := generateOAuthState()
	if err != nil {
		return nil, err
	}
	log.Printf("Open http://localhost:%d for authorization", f.Port)
	code, err := f.getCode(ctx, &f.Config, state)
	if err != nil {
		return nil, err
	}
	token, err := f.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("Could not exchange oauth code: %s", err)
	}
	return token, nil
}

func (f *BrowserAuthCodeFlow) getCode(ctx context.Context, config *oauth2.Config, state string) (string, error) {
	codeCh := make(chan string)
	errCh := make(chan error)
	server := http.Server{
		Addr: fmt.Sprintf(":%d", f.Port),
		Handler: &handler{
			AuthCodeURL: config.AuthCodeURL(state),
			Callback: func(code string, actualState string, err error) {
				switch {
				case err != nil:
					errCh <- err
				case actualState != state:
					errCh <- fmt.Errorf("OAuth state did not match, should be %s but %s", state, actualState)
				default:
					codeCh <- code
				}
			},
		},
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		server.Shutdown(ctx)
		return "", err
	case code := <-codeCh:
		server.Shutdown(ctx)
		return code, nil
	}
}

type handler struct {
	AuthCodeURL string
	Callback    func(code string, state string, err error)
}

func (s *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.RequestURI)
	switch r.URL.Path {
	case "/":
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		errorCode := r.URL.Query().Get("error")
		errorDescription := r.URL.Query().Get("error_description")
		switch {
		case code != "":
			s.Callback(code, state, nil)
			fmt.Fprintf(w, "Back to command line.")
		case errorCode != "":
			s.Callback("", "", fmt.Errorf("OAuth Error: %s %s", errorCode, errorDescription))
			fmt.Fprintf(w, "Back to command line.")
		default:
			http.Redirect(w, r, s.AuthCodeURL, 302)
		}
	default:
		http.Error(w, "Not Found", 404)
	}
}
