package devicecode

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
	ctx := context.TODO()

	t.Run("Authorization error", func(t *testing.T) {
		mockClient := client.NewMockInterface(t)
		dc := &DeviceCode{
			Browser: browser.NewMockInterface(t),
			Logger:  logger.New(t),
		}
		errTest := errors.New("test error")
		mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(nil, errTest).Once()
		_, err := dc.Do(ctx, &Option{}, mockClient)
		if !errors.Is(err, errTest) {
			t.Errorf("returned error is not the test error: %v", err)
		}
	})

	t.Run("Server returns verification_uri_complete", func(t *testing.T) {
		mockBrowser := browser.NewMockInterface(t)
		mockClient := client.NewMockInterface(t)
		dc := &DeviceCode{
			Browser: mockBrowser,
			Logger:  logger.New(t),
		}
		mockResponse := &oauth2dev.AuthorizationResponse{
			DeviceCode:              "device-code-1",
			VerificationURIComplete: "https://example.com/verificationComplete?code=code123",
			ExpiresIn:               2,
			Interval:                1,
		}
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
	})

	t.Run("Server returns verification_uri", func(t *testing.T) {
		mockBrowser := browser.NewMockInterface(t)
		mockClient := client.NewMockInterface(t)
		dc := &DeviceCode{
			Browser: mockBrowser,
			Logger:  logger.New(t),
		}
		mockResponseWithoutComplete := &oauth2dev.AuthorizationResponse{
			DeviceCode:      "device-code-1",
			VerificationURI: "https://example.com/verificationComplete",
			ExpiresIn:       2,
			Interval:        1,
		}
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
		ts, err := dc.Do(ctx, &Option{}, mockClient)
		if err != nil {
			t.Errorf("returned unexpected error: %v", err)
		}
		if ts.IDToken != "test-id-token" {
			t.Errorf("wrong returned tokenset: %v", err)
		}
	})

	t.Run("Server returns verification_url", func(t *testing.T) {
		mockBrowser := browser.NewMockInterface(t)
		mockClient := client.NewMockInterface(t)
		dc := &DeviceCode{
			Browser: mockBrowser,
			Logger:  logger.New(t),
		}
		mockResponse := &oauth2dev.AuthorizationResponse{
			DeviceCode:      "device-code-1",
			VerificationURL: "https://example.com/verificationCompleteURL",
			ExpiresIn:       2,
			Interval:        1,
		}
		mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(mockResponse, nil).Once()
		mockBrowser.EXPECT().Open("https://example.com/verificationCompleteURL").Return(nil).Once()
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
	})

	t.Run("Error when exchanging the device code", func(t *testing.T) {
		mockBrowser := browser.NewMockInterface(t)
		mockClient := client.NewMockInterface(t)
		dc := &DeviceCode{
			Browser: mockBrowser,
			Logger:  logger.New(t),
		}
		mockResponse := &oauth2dev.AuthorizationResponse{
			DeviceCode:              "device-code-1",
			VerificationURIComplete: "https://example.com/verificationComplete?code=code123",
			ExpiresIn:               2,
			Interval:                1,
		}
		mockClient.EXPECT().GetDeviceAuthorization(ctx).Return(&oauth2dev.AuthorizationResponse{
			Interval:                1,
			ExpiresIn:               2,
			VerificationURIComplete: "https://example.com/verificationComplete?code=code123",
			DeviceCode:              "device-code-1",
		}, nil).Once()
		mockBrowser.EXPECT().Open("https://example.com/verificationComplete?code=code123").Return(nil).Once()
		mockClient.EXPECT().ExchangeDeviceCode(mock.Anything, mockResponse).Return(nil, errors.New("test error")).Once()
		_, err := dc.Do(ctx, &Option{}, mockClient)
		if err == nil {
			t.Errorf("did not return error: %v", err)
		}
	})
}

func TestDeviceCode_openURL(t *testing.T) {
	ctx := context.TODO()
	const url = "https://example.com"
	var testError = errors.New("test error")

	t.Run("Continue if error opening the browser", func(t *testing.T) {
		browserMock := browser.NewMockInterface(t)
		deviceCode := &DeviceCode{
			Browser: browserMock,
			Logger:  logger.New(t),
		}
		browserMock.EXPECT().Open(url).Return(testError).Once()
		deviceCode.openURL(ctx, nil, url)
	})

	t.Run("SkipOpenBrowser is set", func(t *testing.T) {
		browserMock := browser.NewMockInterface(t)
		deviceCode := &DeviceCode{
			Browser: browserMock,
			Logger:  logger.New(t),
		}
		deviceCode.openURL(ctx, &Option{SkipOpenBrowser: true}, url)
	})

	t.Run("BrowserCommand is set", func(t *testing.T) {
		browserMock := browser.NewMockInterface(t)
		deviceCode := &DeviceCode{
			Browser: browserMock,
			Logger:  logger.New(t),
		}
		browserMock.EXPECT().OpenCommand(ctx, url, "test-command").Return(testError).Once()
		deviceCode.openURL(ctx, &Option{BrowserCommand: "test-command"}, url)
	})
}
