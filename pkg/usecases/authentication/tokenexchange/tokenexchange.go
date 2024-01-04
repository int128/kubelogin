package tokenexchange

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/usecases/authentication/identifiers"
)

const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

type Option struct {
	resources              []string
	audiences              []string
	requestedTokenType     string
	subjectToken           string
	subjectTokenType       string
	basicAuth              bool
	actorToken             string            // optional
	actorTokenType         string            // required iff ActorToken set
	authRequestExtraParams map[string]string // Optional to provided info like dex connector_id

	// accumulate validation errors
	errors   []error
	warnings []error
}

type TokenExchangeOption func(t Option) Option

func NewTokenExchangeOption(subjectToken, subjectTokenType string, options ...TokenExchangeOption) (*Option, error) {

	t := Option{
		resources: []string{},
		audiences: []string{},

		errors:   []error{},
		warnings: []error{},
	}

	if subjectToken == "" {
		t.errors = append(t.errors, fmt.Errorf("subject_token is required"))
	}

	canonical, err := identifiers.CanonicalTokenType(subjectTokenType)
	if err == nil {
		subjectTokenType = canonical
	} else {
		t.warnings = append(t.warnings, err)
	}

	t.subjectToken = subjectToken
	t.subjectTokenType = subjectTokenType

	for _, o := range options {
		t = o(t)
	}

	if len(t.errors) > 0 {
		// TODO: return contacted list of current errors to user with information
		// about current issues to fix
		err_msg := fmt.Sprintf("Token exchange errors: %d", len(t.errors))
		for _, e := range t.errors {
			err_msg += "\n" + e.Error()

		}
		return nil, fmt.Errorf(err_msg)
	}

	return &t, nil
}

// Support multiple "resource" parameters. Example in
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-resource-indicators-08#section-2.1
func AddResource(resource string) TokenExchangeOption {
	return func(t Option) Option {

		// no-op
		if resource == "" {
			return t
		}

		failed := false
		u, err := url.Parse(resource)

		if err != nil {
			t.errors = append(t.errors, err)
			failed = true
		}

		// adhere to the rfc requirements
		if !u.IsAbs() {
			t.errors = append(t.errors, fmt.Errorf("resource uri must be absolute"))
			failed = true
		}

		if u.Fragment != "" {
			t.errors = append(t.errors, fmt.Errorf("resource uri must not include uri fragement"))
			failed = true
		}

		if !failed {
			t.resources = append(t.resources, resource)
		}
		return t
	}
}

// Support multiple "audience" parameters
func AddAudience(aud string) TokenExchangeOption {
	return func(t Option) Option {
		// no-op
		if aud == "" {
			return t
		}

		t.audiences = append(t.audiences, aud)
		return t
	}
}

// Support multiple "audience" parameters
func SetBasicAuth(useBasicAuth bool) TokenExchangeOption {
	return func(t Option) Option {
		t.basicAuth = useBasicAuth
		return t
	}
}

func AddRequestedTokenType(tokenType string) TokenExchangeOption {
	return func(t Option) Option {

		// no-op
		if tokenType == "" {
			return t
		}

		canonical, err := identifiers.CanonicalTokenType(tokenType)

		// we don't *know* if this is an error. It's just probably an error.
		if err == nil {
			t.requestedTokenType = canonical
		} else {
			// TODO: log a warning
			t.requestedTokenType = tokenType
		}

		return t
	}
}

func AddActorToken(actorToken, actorTokenType string) TokenExchangeOption {
	return func(t Option) Option {

		// no-op
		if actorToken == "" {
			return t
		}

		canonical, err := identifiers.CanonicalTokenType(actorTokenType)

		// we don't *know* if this is an error. It's just probably an error.
		if err == nil {
			t.actorTokenType = canonical
		} else {
			// TODO: log a warning
			t.actorTokenType = actorTokenType
		}

		return t
	}
}

func AddExtraParams(params map[string]string) TokenExchangeOption {
	return func(t Option) Option {
		// no-op
		if t.authRequestExtraParams == nil {
			t.authRequestExtraParams = map[string]string{}
		}

		for k, v := range t.authRequestExtraParams {
			t.authRequestExtraParams[k] = v
		}

		return t
	}
}

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	RefreshToken    string `json:"refresh_token"`

	// errors
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// TokenExchange provides the oauth2 token-exchange flow.
type TokenExchange struct {
	Logger logger.Interface
}

func (u *TokenExchange) Do(ctx context.Context, params *Option, oidcProvider oidc.Provider) (*oidc.TokenSet, error) {
	// u.Logger.V(1).Infof("starting the oauth2 token-exchange flow")

	for _, warn := range params.warnings {
		fmt.Printf("[token-exchange] warning: %v", warn)
	}

	for _, err := range params.errors {
		fmt.Printf("[token-exchange] error: %v", err)
	}
	if len(params.errors) != 0 {
		return nil, params.errors[0]
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	ctx = gooidc.ClientContext(ctx, client)
	discovery, err := gooidc.NewProvider(ctx, oidcProvider.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("token-exchange error: %w", err)
	}

	data := url.Values{}
	data.Add("grant_type", TokenExchangeGrantType)
	for _, aud := range params.audiences {
		data.Add("audience", aud)
	}
	for _, resource := range params.resources {
		data.Add("resource", resource)
	}

	data.Add("scope", strings.Join(oidcProvider.ExtraScopes, " "))

	if params.requestedTokenType != "" {
		data.Add("requested_token_type", params.requestedTokenType)
	}

	fmt.Printf("env %s=%s\n", params.subjectToken, os.Getenv(params.subjectToken))
	if val := os.Getenv(params.subjectToken); val != "" {
		data.Add("subject_token", val)
	} else {
		data.Add("subject_token", params.subjectToken)
	}
	data.Add("subject_token_type", params.subjectTokenType)

	for k, v := range params.authRequestExtraParams {
		data.Add(k, v)
	}

	if !params.basicAuth {
		data.Add("client_id", oidcProvider.ClientID)
		if oidcProvider.ClientSecret != "" {
			data.Add("client_secret", oidcProvider.ClientSecret)
		}
	}

	if params.actorToken != "" {
		if val := os.Getenv(params.actorToken); val != "" {
			data.Add("actor_token", val)
		} else {
			data.Add("actor_token", params.actorToken)
		}
		data.Add("actor_token_type", params.actorTokenType)
	}

	fmt.Println(data.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.Endpoint().TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if params.basicAuth {
		req.SetBasicAuth(oidcProvider.ClientID, oidcProvider.ClientSecret)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token-exchange error: %w", err)
	}
	defer resp.Body.Close()

	var respData tokenExchangeResponse
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return nil, fmt.Errorf("token-exchange error: %w", err)
	}

	if respData.Error != "" {
		return nil, fmt.Errorf("token-exchange error: %s %s %s", respData.Error, respData.ErrorDescription, respData.ErrorURI)
	}

	// u.Logger.V(1).Infof("finished the oauth2 token-exchange flow")
	return &oidc.TokenSet{
		IDToken:      respData.AccessToken,
		RefreshToken: respData.RefreshToken,
	}, nil
}
