package device_code

import (
	"context"
	"errors"
	"testing"

	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/oauth2dev"
	"github.com/stretchr/testify/mock"
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

	mockResponse := &oauth2dev.AuthorizationResponse{DeviceCode: "device-code-1", UserCode: "", VerificationURI: "", VerificationURIComplete: "https://example.com/verificationComplete?code=code123", VerificationURL: "", ExpiresIn: 2, Interval: 1}
	mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(&oauth2dev.AuthorizationResponse{
		Interval:                1,
		ExpiresIn:               2,
		VerificationURIComplete: "https://example.com/verificationComplete?code=code123",
		DeviceCode:              "device-code-1",
	}, nil).Once()
	mockBrowser.EXPECT().Open("https://example.com/verificationComplete?code=code123").Return(nil).Once()
	mockClient.EXPECT().ExchangeDeviceCode(mock.Anything, mockResponse).Return(&oidc.TokenSet{
		IDToken: "test-id-token",
	}, nil).Once()
	ts, err := dc.Do(ctx, &Option{}, mockClient)
	if err != nil {
		t.Errorf("returned unexpected error: %v", err)
	}
	if ts.IDToken != "test-id-token" {
		t.Errorf("wrong returned tokenset: %v", err)
	}

	mockResponseWithoutComplete := &oauth2dev.AuthorizationResponse{DeviceCode: "device-code-1", UserCode: "", VerificationURI: "https://example.com/verificationComplete", VerificationURIComplete: "", VerificationURL: "", ExpiresIn: 2, Interval: 1}
	mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(&oauth2dev.AuthorizationResponse{
		Interval:        1,
		ExpiresIn:       2,
		VerificationURI: "https://example.com/verificationComplete",
		DeviceCode:      "device-code-1",
	}, nil).Once()
	mockBrowser.EXPECT().Open("https://example.com/verificationComplete").Return(nil).Once()
	mockClient.EXPECT().ExchangeDeviceCode(mock.Anything, mockResponseWithoutComplete).Return(&oidc.TokenSet{
		IDToken: "test-id-token",
	}, nil).Once()
	ts, err = dc.Do(ctx, &Option{}, mockClient)
	if err != nil {
		t.Errorf("returned unexpected error: %v", err)
	}
	if ts.IDToken != "test-id-token" {
		t.Errorf("wrong returned tokenset: %v", err)
	}

	mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(&oauth2dev.AuthorizationResponse{
		Interval:                1,
		ExpiresIn:               2,
		VerificationURIComplete: "https://example.com/verificationComplete?code=code123",
		DeviceCode:              "device-code-1",
	}, nil).Once()
	mockBrowser.EXPECT().Open("https://example.com/verificationComplete?code=code123").Return(nil).Once()
	mockClient.EXPECT().ExchangeDeviceCode(mock.Anything, mockResponse).Return(nil, errTest).Once()
	_, err = dc.Do(ctx, &Option{}, mockClient)
	if err == nil {
		t.Errorf("did not return error: %v", err)
	}
}

func TestOPenUrl(t *testing.T) {
	ctx := context.Background()
	browserMock := browser.NewMockInterface(t)
	deviceCode := &DeviceCode{
		Browser: browserMock,
		Logger:  logger.New(t),
	}

	const url = "https://example.com"
	var testError = errors.New("test error")

	browserMock.EXPECT().Open(url).Return(testError).Once()
	deviceCode.openURL(ctx, nil, url)

	deviceCode.openURL(ctx, &Option{SkipOpenBrowser: true}, url)

	browserMock.EXPECT().OpenCommand(ctx, url, "test-command").Return(testError).Once()
	deviceCode.openURL(ctx, &Option{BrowserCommand: "test-command"}, url)
}
