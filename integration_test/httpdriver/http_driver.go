// Package httpdriver provides a test double of the browser.
package httpdriver

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
)

type Option struct {
	TLSConfig    *tls.Config
	BodyContains string
}

// New returns a client to simulate browser access.
func New(ctx context.Context, t *testing.T, o Option) *client {
	return &client{ctx, t, o}
}

// Zero returns a client which call is not expected.
func Zero(t *testing.T) *zeroClient {
	return &zeroClient{t}
}

type client struct {
	ctx context.Context
	t   *testing.T
	o   Option
}

func (c *client) Open(url string) error {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: c.o.TLSConfig}}
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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Errorf("could not read body: %s", err)
		return nil
	}
	body := string(b)
	if !strings.Contains(body, c.o.BodyContains) {
		c.t.Errorf("body should contain %s but was %s", c.o.BodyContains, body)
	}
	return nil
}

func (c *client) OpenCommand(_ context.Context, url, _ string) error {
	return c.Open(url)
}

type zeroClient struct {
	t *testing.T
}

func (c *zeroClient) Open(url string) error {
	c.t.Errorf("unexpected function call Open(%s)", url)
	return nil
}

func (c *zeroClient) OpenCommand(_ context.Context, url, _ string) error {
	return c.Open(url)
}
