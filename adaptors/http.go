package adaptors

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/int128/kubelogin/adaptors/interfaces"
)

type HTTP struct{}

func (*HTTP) NewClient(in adaptors.HTTPClientIn) (*http.Client, error) {
	transport := &http.Transport{}
	//TODO: replace with http.ProxyFromEnvironmentURL or go-ieproxy
	// https://github.com/int128/kubelogin/issues/31
	val, ok := os.LookupEnv("HTTPS_PROXY")
	if ok {
		proxyURL, err := url.Parse(val)
		if err != nil {
			log.Printf("HTTPS_PROXY %s cannot be parsed into a URL\n", val)
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	//
	transport.TLSClientConfig = in.TLSClientConfig
	return &http.Client{Transport: transport}, nil
}
