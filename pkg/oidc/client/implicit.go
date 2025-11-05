package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/int128/kubelogin/pkg/oidc"
	"golang.org/x/oauth2"
)

type GetTokenByImplicitFlowInput struct {
	BindAddress            []string
	State                  string
	Nonce                  string
	AuthRequestExtraParams map[string]string
	LocalServerSuccessHTML string
	LocalServerCertFile    string
	LocalServerKeyFile     string
}

// GetTokenByImplicitFlow performs the implicit flow with id_token
func (c *client) GetTokenByImplicitFlow(ctx context.Context, in GetTokenByImplicitFlowInput, localServerReadyChan chan<- string) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)

	tokenChan := make(chan map[string]string, 1)
	errChan := make(chan error, 1)

	server, serverURL, err := c.startImplicitFlowServer(ctx, in, tokenChan, errChan)
	if err != nil {
		return nil, fmt.Errorf("failed to start local server: %w", err)
	}
	defer func() {
		_ = server.Shutdown(context.Background())
	}()

	authURL := c.buildImplicitFlowAuthURL(serverURL, in.State, in.Nonce, in.AuthRequestExtraParams)

	if localServerReadyChan != nil {
		c.logger.V(1).Infof("Local server ready at %s", serverURL)
		c.logger.V(1).Infof("Authorization URL: %s", authURL)
		localServerReadyChan <- authURL
	}

	select {
	case tokens := <-tokenChan:
		return c.processImplicitFlowTokens(ctx, tokens, in.State, in.Nonce)
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}
}

// buildImplicitFlowAuthURL creates the authorization URL for implicit flow
func (c *client) buildImplicitFlowAuthURL(redirectURI, state, nonce string, extraParams map[string]string) string {
	params := url.Values{}
	params.Set("client_id", c.oauth2Config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "id_token")

	scopes := append([]string{"openid"}, c.oauth2Config.Scopes...)
	params.Set("scope", strings.Join(scopes, " "))

	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("response_mode", "fragment")

	for key, value := range extraParams {
		params.Set(key, value)
	}

	return c.oauth2Config.Endpoint.AuthURL + "?" + params.Encode()
}

// startImplicitFlowServer starts a local HTTP server to capture the implicit flow redirect
func (c *client) startImplicitFlowServer(ctx context.Context, in GetTokenByImplicitFlowInput, tokenChan chan<- map[string]string, errChan chan<- error) (*http.Server, string, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := c.getFragmentExtractorHTML(in.LocalServerSuccessHTML)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			errChan <- fmt.Errorf("failed to parse form: %w", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		tokens := map[string]string{
			"id_token":          r.FormValue("id_token"),
			"state":             r.FormValue("state"),
			"error":             r.FormValue("error"),
			"error_description": r.FormValue("error_description"),
		}

		if tokens["error"] != "" {
			errChan <- fmt.Errorf("authorization error: %s - %s", tokens["error"], tokens["error_description"])
			http.Error(w, "Authorization failed", http.StatusBadRequest)
			return
		}

		tokenChan <- tokens

		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			return
		}
	})

	var server *http.Server
	var serverURL string
	var lastErr error

	for _, addr := range in.BindAddress {
		server = &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		go func() {
			var err error
			if in.LocalServerCertFile != "" && in.LocalServerKeyFile != "" {
				err = server.ListenAndServeTLS(in.LocalServerCertFile, in.LocalServerKeyFile)
			} else {
				err = server.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				c.logger.V(1).Infof("Server error: %v", err)
			}
		}()

		time.Sleep(100 * time.Millisecond)

		scheme := "http"
		if in.LocalServerCertFile != "" {
			scheme = "https"
		}
		serverURL = fmt.Sprintf("%s://%s", scheme, addr)

		c.logger.V(1).Infof("Started server on %s", serverURL)
		return server, serverURL, nil
	}

	return nil, "", fmt.Errorf("failed to start server on any address: %w", lastErr)
}

// getFragmentExtractorHTML returns HTML with JavaScript to extract tokens from URL fragment and send it to the backend.
func (c *client) getFragmentExtractorHTML(successHTML string) string {
	if successHTML != "" {
		return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Authentication</title></head>
<body>
<script>
const hash = window.location.hash.substring(1);
const params = new URLSearchParams(hash);

const formData = new URLSearchParams();
formData.append('id_token', params.get('id_token') || '');
formData.append('access_token', params.get('access_token') || '');
formData.append('state', params.get('state') || '');
formData.append('error', params.get('error') || '');
formData.append('error_description', params.get('error_description') || '');

fetch('/callback', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: formData
}).then(() => {
    document.body.innerHTML = %s;
}).catch(err => {
    document.body.innerHTML = '<h1>Error</h1><p>' + err + '</p>';
});
</script>
<p>Processing authentication...</p>
</body>
</html>`, quoteJavaScriptString(successHTML))
	}

	return `<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body>
<script>
const hash = window.location.hash.substring(1);
const params = new URLSearchParams(hash);

const formData = new URLSearchParams();
formData.append('id_token', params.get('id_token') || '');
formData.append('access_token', params.get('access_token') || '');
formData.append('state', params.get('state') || '');
formData.append('error', params.get('error') || '');
formData.append('error_description', params.get('error_description') || '');

fetch('/callback', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: formData
}).then(() => {
    document.body.innerHTML = '<h1>Authentication Successful</h1><p>You can close this window.</p>';
}).catch(err => {
    document.body.innerHTML = '<h1>Error</h1><p>' + err + '</p>';
});
</script>
<p>Processing authentication...</p>
</body>
</html>`
}

// processImplicitFlowTokens validates and processes the tokens from implicit flow
func (c *client) processImplicitFlowTokens(ctx context.Context, tokens map[string]string, expectedState, expectedNonce string) (*oidc.TokenSet, error) {
	if tokens["state"] != expectedState {
		return nil, fmt.Errorf("state mismatch: expected %s, got %s", expectedState, tokens["state"])
	}

	idToken := tokens["id_token"]
	if idToken == "" {
		return nil, fmt.Errorf("no id_token in response")
	}

	// Implicit flow shouldn't have an access_token, check anyway
	token := &oauth2.Token{
		AccessToken: tokens["access_token"],
		TokenType:   "Bearer",
	}
	token = token.WithExtra(map[string]interface{}{
		"id_token": idToken,
	})

	return c.verifyToken(ctx, token, expectedNonce)
}

func quoteJavaScriptString(s string) string {
	// Escape for JavaScript string literal
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return "'" + s + "'"
}
