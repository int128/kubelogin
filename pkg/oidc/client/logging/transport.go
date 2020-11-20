package logging

import (
	"net/http"
	"net/http/httputil"

	"github.com/int128/kubelogin/pkg/infrastructure/logger"
)

const (
	levelDumpHeaders = 2
	levelDumpBody    = 3
)

type Transport struct {
	Base   http.RoundTripper
	Logger logger.Interface
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.Logger.IsEnabled(levelDumpHeaders) {
		return t.Base.RoundTrip(req)
	}

	reqDump, err := httputil.DumpRequestOut(req, t.Logger.IsEnabled(levelDumpBody))
	if err != nil {
		t.Logger.V(levelDumpHeaders).Infof("could not dump the request: %s", err)
		return t.Base.RoundTrip(req)
	}
	t.Logger.V(levelDumpHeaders).Infof("%s", string(reqDump))
	resp, err := t.Base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	respDump, err := httputil.DumpResponse(resp, t.Logger.IsEnabled(levelDumpBody))
	if err != nil {
		t.Logger.V(levelDumpHeaders).Infof("could not dump the response: %s", err)
		return resp, err
	}
	t.Logger.V(levelDumpHeaders).Infof("%s", string(respDump))
	return resp, err
}
