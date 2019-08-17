package logging

import (
	"net/http"
	"net/http/httputil"

	"github.com/int128/kubelogin/pkg/adaptors"
)

const (
	logLevelDumpHeaders = 2
	logLevelDumpBody    = 3
)

type Transport struct {
	Base   http.RoundTripper
	Logger adaptors.Logger
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.IsDumpEnabled() {
		return t.Base.RoundTrip(req)
	}

	reqDump, err := httputil.DumpRequestOut(req, t.IsDumpBodyEnabled())
	if err != nil {
		t.Logger.Debugf(logLevelDumpHeaders, "could not dump the request: %s", err)
		return t.Base.RoundTrip(req)
	}
	t.Logger.Debugf(logLevelDumpHeaders, "%s", string(reqDump))
	resp, err := t.Base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	respDump, err := httputil.DumpResponse(resp, t.IsDumpBodyEnabled())
	if err != nil {
		t.Logger.Debugf(logLevelDumpHeaders, "could not dump the response: %s", err)
		return resp, err
	}
	t.Logger.Debugf(logLevelDumpHeaders, "%s", string(respDump))
	return resp, err
}

func (t *Transport) IsDumpEnabled() bool {
	return t.Logger.IsEnabled(logLevelDumpHeaders)
}

func (t *Transport) IsDumpBodyEnabled() bool {
	return t.Logger.IsEnabled(logLevelDumpBody)
}
