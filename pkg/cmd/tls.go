package cmd

import (
	"crypto/tls"

	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/spf13/pflag"
)

type tlsOptions struct {
	CACertFilename            []string
	CACertData                []string
	SkipTLSVerify             bool
	RenegotiateOnceAsClient   bool
	RenegotiateFreelyAsClient bool
}

func (o *tlsOptions) addFlags(f *pflag.FlagSet) {
	f.StringArrayVar(&o.CACertFilename, "certificate-authority", nil, "Path to a cert file for the certificate authority")
	f.StringArrayVar(&o.CACertData, "certificate-authority-data", nil, "Base64 encoded cert for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If set, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	f.BoolVar(&o.RenegotiateOnceAsClient, "tls-renegotiation-once", false, "If set, allow a remote server to request renegotiation once per connection")
	f.BoolVar(&o.RenegotiateFreelyAsClient, "tls-renegotiation-freely", false, "If set, allow a remote server to repeatedly request renegotiation")
}

func (o *tlsOptions) expandHomedir() {
	var caCertFilenames []string
	for _, caCertFilename := range o.CACertFilename {
		expanded := expandHomedir(caCertFilename)
		caCertFilenames = append(caCertFilenames, expanded)
	}
	o.CACertFilename = caCertFilenames
}

func (o tlsOptions) tlsClientConfig() tlsclientconfig.Config {
	return tlsclientconfig.Config{
		CACertFilename: o.CACertFilename,
		CACertData:     o.CACertData,
		SkipTLSVerify:  o.SkipTLSVerify,
		Renegotiation:  o.renegotiationSupport(),
	}
}

func (o tlsOptions) renegotiationSupport() tls.RenegotiationSupport {
	if o.RenegotiateOnceAsClient {
		return tls.RenegotiateOnceAsClient
	}
	if o.RenegotiateFreelyAsClient {
		return tls.RenegotiateFreelyAsClient
	}
	return tls.RenegotiateNever
}
