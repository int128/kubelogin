package client

import (
	"net/url"
	"testing"

	"github.com/int128/kubelogin/pkg/pkce"
	"golang.org/x/oauth2"
)

func Test_authorizationRequestOptions_accessType(t *testing.T) {
	config := oauth2.Config{
		ClientID: "YOUR_CLIENT_ID",
		Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example.com/authorize"},
	}
	tests := map[string]string{
		"":        "offline",
		"offline": "offline",
		"online":  "online",
	}
	for accessType, want := range tests {
		t.Run("accessType="+accessType, func(t *testing.T) {
			opts := authorizationRequestOptions("NONCE", pkce.Params{}, nil, accessType)
			authCodeURL := config.AuthCodeURL("STATE", opts...)
			u, err := url.Parse(authCodeURL)
			if err != nil {
				t.Fatalf("could not parse the authorization URL: %s", err)
			}
			if got := u.Query().Get("access_type"); got != want {
				t.Errorf("access_type wants %s but was %s", want, got)
			}
		})
	}
}
