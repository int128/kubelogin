package transport

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/int128/kubelogin/pkg/testing/logger"
)

type mockTransport struct {
	req  *http.Request
	resp *http.Response
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.req = req
	return t.resp, nil
}

func TestWithLogging_RoundTrip(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/hello", nil)
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(`HTTP/1.1 200 OK
Host: example.com

dummy`)), req)
	if err != nil {
		t.Errorf("could not create a response: %s", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("could not close response body: %s", err)
		}
	}()

	transport := &WithLogging{
		Base:   &mockTransport{resp: resp},
		Logger: logger.New(t),
	}
	gotResp, err := transport.RoundTrip(req)
	if err != nil {
		t.Errorf("RoundTrip error: %s", err)
	}
	if gotResp != resp {
		t.Errorf("resp wants %v but %v", resp, gotResp)
	}
}
