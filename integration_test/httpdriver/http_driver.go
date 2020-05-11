// Package httpdriver provides a test double of the browser.
package httpdriver

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
)

// New returns a client to simulate browser access.
func New(ctx context.Context, t *testing.T, tlsConfig *tls.Config) *client {
	return &client{ctx, t, tlsConfig}
}

// Zero returns a client which call is not expected.
func Zero(t *testing.T) *zeroClient {
	return &zeroClient{t}
}

type client struct {
	ctx       context.Context
	t         *testing.T
	tlsConfig *tls.Config
}

func (c *client) Open(url string) error {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: c.tlsConfig}}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.t.Errorf("could not create a request: %s", err)
		return nil
	}
	req = req.WithContext(c.ctx)
	resp, err := client.Do(req)
	if err != nil {
		c.t.Errorf("could not send a request: %s", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		c.t.Errorf("StatusCode wants 200 but %d", resp.StatusCode)
	}
	return nil
}

type zeroClient struct {
	t *testing.T
}

func (c *zeroClient) Open(url string) error {
	c.t.Errorf("unexpected function call Open(%s)", url)
	return nil
}
