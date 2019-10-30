package setup

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/certpool/mock_certpool"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/mock_authentication"
)

func TestSetup_DoStage2(t *testing.T) {
	var authCodeOption authentication.AuthCodeOption
	var ropcOption authentication.ROPCOption
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
		AuthCodeOption: &authCodeOption,
		ROPCOption:     &ropcOption,
	}

	mockCertPool := mock_certpool.NewMockInterface(ctrl)
	mockCertPool.EXPECT().
		AddFile("/path/to/cert")
	mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
	mockCertPoolFactory.EXPECT().
		New().
		Return(mockCertPool)
	mockAuthentication := mock_authentication.NewMockInterface(ctrl)
	mockAuthentication.EXPECT().
		Do(ctx, authentication.Input{
			IssuerURL:      "https://accounts.google.com",
			ClientID:       "YOUR_CLIENT_ID",
			ClientSecret:   "YOUR_CLIENT_SECRET",
			ExtraScopes:    []string{"email"},
			CertPool:       mockCertPool,
			SkipTLSVerify:  true,
			AuthCodeOption: &authCodeOption,
			ROPCOption:     &ropcOption,
		}).
		Return(&authentication.Output{
			IDToken:        "YOUR_ID_TOKEN",
			RefreshToken:   "YOUR_REFRESH_TOKEN",
			IDTokenSubject: "YOUR_SUBJECT",
			IDTokenExpiry:  time.Now().Add(time.Hour),
			IDTokenClaims:  map[string]string{"iss": "https://accounts.google.com"},
		}, nil)
	u := Setup{
		Authentication:  mockAuthentication,
		CertPoolFactory: mockCertPoolFactory,
		Logger:          mock_logger.New(t),
	}
	if err := u.DoStage2(ctx, in); err != nil {
		t.Errorf("DoStage2 returned error: %+v", err)
	}
}
