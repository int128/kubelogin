package setup

import (
	"context"
	"testing"
	"time"

	"github.com/int128/kubelogin/pkg/oidc"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/stretchr/testify/assert"
)

func TestSetup_DoStage2(t *testing.T) {
	issuedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
		claims.Issuer = "https://issuer.example.com"
		claims.Subject = "YOUR_SUBJECT"
		claims.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
	})
	dummyTLSClientConfig := tlsclientconfig.Config{
		CACertFilename: []string{"/path/to/cert"},
	}
	var grantOptionSet authentication.GrantOptionSet

	ctx := context.Background()
	in := Stage2Input{
		IssuerURL:       "https://accounts.google.com",
		ClientID:        "YOUR_CLIENT_ID",
		ClientSecret:    "YOUR_CLIENT_SECRET",
		ExtraScopes:     []string{"email"},
		GrantOptionSet:  grantOptionSet,
		TLSClientConfig: dummyTLSClientConfig,
	}
	mockAuthentication := authentication.NewMockInterface(t)
	mockAuthentication.EXPECT().
		Do(ctx, authentication.Input{
			Provider: oidc.Provider{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				ExtraScopes:  []string{"email"},
			},
			GrantOptionSet:  grantOptionSet,
			TLSClientConfig: dummyTLSClientConfig,
		}).
		Return(&authentication.Output{
			TokenSet: oidc.TokenSet{
				IDToken:      issuedIDToken,
				RefreshToken: "YOUR_REFRESH_TOKEN",
			},
		}, nil)
	u := Setup{
		Authentication: mockAuthentication,
		Logger:         logger.New(t),
	}
	if err := u.DoStage2(ctx, in); err != nil {
		t.Errorf("DoStage2 returned error: %+v", err)
	}
}

func Test_makeCredentialPluginArgs(t *testing.T) {
	in := Stage2Input{
		IssuerURL:         "https://oidc.example.com",
		ClientID:          "test_kid",
		ClientSecret:      "test_ksecret",
		ExtraScopes:       []string{"groups"},
		UsePKCE:           true,
		ListenAddressArgs: []string{"127.0.0.1:8080", "127.0.0.1:8888"},
		GrantOptionSet: authentication.GrantOptionSet{
			AuthCodeBrowserOption: &authcode.BrowserOption{
				SkipOpenBrowser:     true,
				BrowserCommand:      "firefox",
				LocalServerCertFile: "/path/to/cert.crt",
				LocalServerKeyFile:  "/path/to/cert.key",
			},
			ROPCOption: &ropc.Option{
				Username: "user1",
			},
		},
		TLSClientConfig: tlsclientconfig.Config{
			CACertFilename: []string{"/path/to/ca.crt"},
			CACertData:     []string{"base64encoded1"},
			SkipTLSVerify:  true,
		},
	}
	expet := []string{
		"--oidc-issuer-url=https://oidc.example.com",
		"--oidc-client-id=test_kid",
		"--oidc-client-secret=test_ksecret",
		"--oidc-extra-scope=groups",
		"--oidc-use-pkce",
		"--certificate-authority=/path/to/ca.crt",
		"--certificate-authority-data=base64encoded1",
		"--insecure-skip-tls-verify",
		"--skip-open-browser",
		"--browser-command=firefox",
		"--local-server-cert=/path/to/cert.crt",
		"--local-server-key=/path/to/cert.key",
		"--listen-address=127.0.0.1:8080",
		"--listen-address=127.0.0.1:8888",
		"--username=user1",
	}
	got := makeCredentialPluginArgs(in)
	assert.Equal(t, expet, got)
}
