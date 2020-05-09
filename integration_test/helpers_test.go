package integration_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/browser/mock_browser"
)

var (
	tokenExpiryFuture = time.Now().Add(time.Hour).Round(time.Second)
	tokenExpiryPast   = time.Now().Add(-time.Hour).Round(time.Second)
)

func newBrowserMock(ctx context.Context, t *testing.T, ctrl *gomock.Controller, k keypair.KeyPair) browser.Interface {
	b := mock_browser.NewMockInterface(ctrl)
	b.EXPECT().
		Open(gomock.Any()).
		Do(func(url string) {
			client := http.Client{Transport: &http.Transport{TLSClientConfig: k.TLSConfig}}
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Errorf("could not create a request: %s", err)
				return
			}
			req = req.WithContext(ctx)
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("could not send a request: %s", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("StatusCode wants 200 but %d", resp.StatusCode)
			}
		})
	return b
}
