package infrastructure

import (
	"net/http"
	"net/http/httputil"

	"github.com/int128/kubelogin/adaptors"
)

const (
	logLevelDumpHeaders = 2
	logLevelDumpBody    = 3
)

type LoggingTransport struct {
	Base   http.RoundTripper
	Logger adaptors.Logger
}

func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.IsDumpEnabled() {
		return t.Base.RoundTrip(req)
	}

	reqDump, err := httputil.DumpRequestOut(req, t.IsDumpBodyEnabled())
	if err != nil {
		t.Logger.Debugf(logLevelDumpHeaders, "Error: could not dump the request: %s", err)
		return t.Base.RoundTrip(req)
	}
	t.Logger.Debugf(logLevelDumpHeaders, "%s", string(reqDump))
	resp, err := t.Base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	respDump, err := httputil.DumpResponse(resp, t.IsDumpBodyEnabled())
	if err != nil {
		t.Logger.Debugf(logLevelDumpHeaders, "Error: could not dump the response: %s", err)
		return resp, err
	}
	t.Logger.Debugf(logLevelDumpHeaders, "%s", string(respDump))
	return resp, err
}

func (t *LoggingTransport) IsDumpEnabled() bool {
	return t.Logger.IsEnabled(logLevelDumpHeaders)
}

func (t *LoggingTransport) IsDumpBodyEnabled() bool {
	return t.Logger.IsEnabled(logLevelDumpBody)
}
