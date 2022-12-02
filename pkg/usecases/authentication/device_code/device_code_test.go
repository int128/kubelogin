package device_code

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

func TestDeviceCode(t *testing.T) {
	mockBrowser := browser.NewMockInterface(t)
	logger := logger.New(t)
	mockClient := client.NewMockInterface(t)

	dc := &DeviceCode{
		Browser: mockBrowser,
		Logger:  logger,
	}

	ctx := context.Background()
	errTest := errors.New("test error")

	mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(nil, errTest).Once()
	_, err := dc.Do(ctx, &Option{}, mockClient)
	if !errors.Is(err, errTest) {
		t.Errorf("returned error is not the test error: %v", err)
	}

	mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(&client.DeviceRequest{
		Interval:        1,
		VerificationURI: "https://example.com/verification",
	}, nil).Once()
	mockBrowser.EXPECT().Open("https://example.com/verification").Return(nil).Once()
	_, err = dc.Do(ctx, &Option{}, mockClient)
	if !errors.Is(err, errExpired) {
		t.Errorf("returned error is not the expired error: %v", err)
	}

	mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(&client.DeviceRequest{
		Interval:                1,
		VerificationURIComplete: "https://example.com/verificationComplete?code=code123",
	}, nil).Once()
	mockBrowser.EXPECT().Open("https://example.com/verificationComplete?code=code123").Return(nil).Once()
	_, err = dc.Do(ctx, &Option{}, mockClient)
	if !errors.Is(err, errExpired) {
		t.Errorf("returned error is not the expired error: %v", err)
	}

	mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(&client.DeviceRequest{
		Interval:                1,
		ExpiresIn:               2,
		VerificationURIComplete: "https://example.com/verificationComplete?code=code123",
		DeviceCode:              "device-code-1",
	}, nil).Once()
	mockClient.EXPECT().ExchangeDeviceCode(mock.Anything, "device-code-1").Return(nil, &oauth2.RetrieveError{
		Body: []byte(`{"error": "authorization_pending"}`),
	}).Once()
	mockClient.EXPECT().ExchangeDeviceCode(mock.Anything, "device-code-1").Return(&oidc.TokenSet{
		IDToken: "test-id-token",
	}, nil).Once()
	mockBrowser.EXPECT().Open("https://example.com/verificationComplete?code=code123").Return(nil).Once()
	ts, err := dc.Do(ctx, &Option{}, mockClient)
	if err != nil {
		t.Errorf("returned unexpected error: %v", err)
	}
	if ts.IDToken != "test-id-token" {
		t.Errorf("wrong returned tokenset: %v", err)
	}

	mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(&client.DeviceRequest{
		Interval:                1,
		ExpiresIn:               2,
		VerificationURIComplete: "https://example.com/verificationComplete?code=code123",
		DeviceCode:              "device-code-1",
	}, nil).Once()
	mockBrowser.EXPECT().Open("https://example.com/verificationComplete?code=code123").Return(nil).Once()
	mockClient.EXPECT().ExchangeDeviceCode(mock.Anything, "device-code-1").Return(nil, &oauth2.RetrieveError{
		Response: &http.Response{},
		Body:     []byte(`{"error": "invalid_client"}`),
	}).Once()
	_, err = dc.Do(ctx, &Option{}, mockClient)
	if err == nil {
		t.Errorf("did not return error: %v", err)
	}
}
