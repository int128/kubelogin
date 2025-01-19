package cmd

import (
	"crypto/tls"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/spf13/pflag"
)

func Test_tlsOptions_tlsClientConfig(t *testing.T) {
	tests := map[string]struct {
		args []string
		want tlsclientconfig.Config
	}{
		"NoFlag": {},
		"SkipTLSVerify": {
			args: []string{
				"--insecure-skip-tls-verify",
			},
			want: tlsclientconfig.Config{
				SkipTLSVerify: true,
			},
		},
		"CACertFilename1": {
			args: []string{
				"--certificate-authority", "/path/to/cert1",
			},
			want: tlsclientconfig.Config{
				CACertFilename: []string{"/path/to/cert1"},
			},
		},
		"CACertFilename2": {
			args: []string{
				"--certificate-authority", "/path/to/cert1",
				"--certificate-authority", "/path/to/cert2",
			},
			want: tlsclientconfig.Config{
				CACertFilename: []string{"/path/to/cert1", "/path/to/cert2"},
			},
		},
		"CACertData1": {
			args: []string{
				"--certificate-authority-data", "base64encoded1",
			},
			want: tlsclientconfig.Config{
				CACertData: []string{"base64encoded1"},
			},
		},
		"CACertData2": {
			args: []string{
				"--certificate-authority-data", "base64encoded1",
				"--certificate-authority-data", "base64encoded2",
			},
			want: tlsclientconfig.Config{
				CACertData: []string{"base64encoded1", "base64encoded2"},
			},
		},
		"RenegotiateOnceAsClient": {
			args: []string{
				"--tls-renegotiation-once",
			},
			want: tlsclientconfig.Config{
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
		},
		"RenegotiateFreelyAsClient": {
			args: []string{
				"--tls-renegotiation-freely",
			},
			want: tlsclientconfig.Config{
				Renegotiation: tls.RenegotiateFreelyAsClient,
			},
		},
	}

	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			var o tlsOptions
			f := pflag.NewFlagSet("", pflag.ContinueOnError)
			o.addFlags(f)
			if err := f.Parse(c.args); err != nil {
				t.Fatalf("Parse error: %s", err)
			}
			got := o.tlsClientConfig()
			if diff := cmp.Diff(c.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
