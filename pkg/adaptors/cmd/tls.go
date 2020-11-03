package cmd

import (
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/spf13/pflag"
)

type tlsOptions struct {
	CACertFilename []string
	CACertData     []string
	SkipTLSVerify  bool
}

func (o *tlsOptions) addFlags(f *pflag.FlagSet) {
	f.StringArrayVar(&o.CACertFilename, "certificate-authority", nil, "Path to a cert file for the certificate authority")
	f.StringArrayVar(&o.CACertData, "certificate-authority-data", nil, "Base64 encoded cert for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If set, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
}

func (o *tlsOptions) tlsClientConfig() tlsclientconfig.Config {
	return tlsclientconfig.Config{
		CACertFilename: o.CACertFilename,
		CACertData:     o.CACertData,
		SkipTLSVerify:  o.SkipTLSVerify,
	}
}
