package logging

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
)

type mockTransport struct {
	req  *http.Request
	resp *http.Response
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.req = req
	return t.resp, nil
}

func TestLoggingTransport_RoundTrip(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := mock_adaptors.NewLogger(t, ctrl)
	logger.EXPECT().
		IsEnabled(gomock.Any()).
		Return(true).
		AnyTimes()

	req := httptest.NewRequest("GET", "http://example.com/hello", nil)
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(`HTTP/1.1 200 OK
Host: example.com

dummy`)), req)
	if err != nil {
		t.Errorf("could not create a response: %s", err)
	}
	defer resp.Body.Close()

	transport := &Transport{
		Base:   &mockTransport{resp: resp},
		Logger: logger,
	}
	gotResp, err := transport.RoundTrip(req)
	if err != nil {
		t.Errorf("RoundTrip error: %s", err)
	}
	if gotResp != resp {
		t.Errorf("resp wants %v but %v", resp, gotResp)
	}
}

func TestLoggingTransport_IsDumpEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := mock_adaptors.NewLogger(t, ctrl)
	logger.EXPECT().
		IsEnabled(adaptors.LogLevel(logLevelDumpHeaders)).
		Return(true)

	transport := &Transport{
		Logger: logger,
	}
	if transport.IsDumpEnabled() != true {
		t.Errorf("IsDumpEnabled wants true")
	}
}

func TestLoggingTransport_IsDumpBodyEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := mock_adaptors.NewLogger(t, ctrl)
	logger.EXPECT().
		IsEnabled(adaptors.LogLevel(logLevelDumpBody)).
		Return(true)

	transport := &Transport{
		Logger: logger,
	}
	if transport.IsDumpBodyEnabled() != true {
		t.Errorf("IsDumpBodyEnabled wants true")
	}
}
