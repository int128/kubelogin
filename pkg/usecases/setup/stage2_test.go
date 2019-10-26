package setup

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/usecases/auth"
	"github.com/int128/kubelogin/pkg/usecases/auth/mock_auth"
)

func TestSetup_DoStage2(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx := context.Background()

	in := Stage2Input{
		IssuerURL:       "https://accounts.google.com",
		ClientID:        "YOUR_CLIENT_ID",
		ClientSecret:    "YOUR_CLIENT_SECRET",
		ExtraScopes:     []string{"email"},
		SkipOpenBrowser: true,
		BindAddress:     []string{"127.0.0.1:8000"},
		CACertFilename:  "/path/to/cert",
		SkipTLSVerify:   true,
	}

	mockAuthentication := mock_auth.NewMockInterface(ctrl)
	mockAuthentication.EXPECT().
		Do(ctx, auth.Input{
			OIDCConfig: kubeconfig.OIDCConfig{
				IDPIssuerURL: "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				ExtraScopes:  []string{"email"},
			},
			SkipOpenBrowser: true,
			BindAddress:     []string{"127.0.0.1:8000"},
			CACertFilename:  "/path/to/cert",
			SkipTLSVerify:   true,
		}).
		Return(&auth.Output{
			IDToken:        "YOUR_ID_TOKEN",
			RefreshToken:   "YOUR_REFRESH_TOKEN",
			IDTokenSubject: "YOUR_SUBJECT",
			IDTokenExpiry:  time.Now().Add(time.Hour),
			IDTokenClaims:  map[string]string{"iss": "https://accounts.google.com"},
		}, nil)
	u := Setup{
		Authentication: mockAuthentication,
		Logger:         mock_logger.New(t),
	}
	if err := u.DoStage2(ctx, in); err != nil {
		t.Errorf("DoStage2 returned error: %+v", err)
	}
}
