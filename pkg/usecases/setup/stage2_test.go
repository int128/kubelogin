package setup

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/certpool/mock_certpool"
	"github.com/int128/kubelogin/pkg/oidc"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/mock_authentication"
)

func TestSetup_DoStage2(t *testing.T) {
	issuedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
		claims.Issuer = "https://issuer.example.com"
		claims.Subject = "YOUR_SUBJECT"
		claims.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
	})

	var grantOptionSet authentication.GrantOptionSet
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx := context.Background()

	in := Stage2Input{
		IssuerURL:      "https://accounts.google.com",
		ClientID:       "YOUR_CLIENT_ID",
		ClientSecret:   "YOUR_CLIENT_SECRET",
		ExtraScopes:    []string{"email"},
		CACertFilename: "/path/to/cert",
		SkipTLSVerify:  true,
		GrantOptionSet: grantOptionSet,
	}

	mockCertPool := mock_certpool.NewMockInterface(ctrl)
	mockCertPool.EXPECT().
		AddFile("/path/to/cert")
	mockAuthentication := mock_authentication.NewMockInterface(ctrl)
	mockAuthentication.EXPECT().
		Do(ctx, authentication.Input{
			Provider: oidc.Provider{
				IssuerURL:     "https://accounts.google.com",
				ClientID:      "YOUR_CLIENT_ID",
				ClientSecret:  "YOUR_CLIENT_SECRET",
				ExtraScopes:   []string{"email"},
				CertPool:      mockCertPool,
				SkipTLSVerify: true,
			},
			GrantOptionSet: grantOptionSet,
		}).
		Return(&authentication.Output{
			TokenSet: oidc.TokenSet{
				IDToken:      issuedIDToken,
				RefreshToken: "YOUR_REFRESH_TOKEN",
			},
		}, nil)
	u := Setup{
		Authentication: mockAuthentication,
		NewCertPool:    func() certpool.Interface { return mockCertPool },
		Logger:         logger.New(t),
	}
	if err := u.DoStage2(ctx, in); err != nil {
		t.Errorf("DoStage2 returned error: %+v", err)
	}
}
