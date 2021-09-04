package cmd

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/spf13/pflag"
)

func Test_authenticationOptions_grantOptionSet(t *testing.T) {
	tests := map[string]struct {
		args []string
		want authentication.GrantOptionSet
	}{
		"NoFlag": {
			want: authentication.GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:           defaultListenAddress,
					AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
					RedirectURLHostname:   "localhost",
				},
			},
		},
		"FullOptions": {
			args: []string{
				"--grant-type", "authcode",
				"--listen-address", "127.0.0.1:10080",
				"--listen-address", "127.0.0.1:20080",
				"--skip-open-browser",
				"--browser-command", "firefox",
				"--authentication-timeout-sec", "10",
				"--local-server-cert", "/path/to/local-server-cert",
				"--local-server-key", "/path/to/local-server-key",
				"--open-url-after-authentication", "https://example.com/success.html",
				"--oidc-redirect-url-hostname", "example",
				"--oidc-auth-request-extra-params", "ttl=86400",
				"--oidc-auth-request-extra-params", "reauth=true",
				"--username", "USER",
				"--password", "PASS",
			},
			want: authentication.GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:                []string{"127.0.0.1:10080", "127.0.0.1:20080"},
					SkipOpenBrowser:            true,
					BrowserCommand:             "firefox",
					AuthenticationTimeout:      10 * time.Second,
					LocalServerCertFile:        "/path/to/local-server-cert",
					LocalServerKeyFile:         "/path/to/local-server-key",
					OpenURLAfterAuthentication: "https://example.com/success.html",
					RedirectURLHostname:        "example",
					AuthRequestExtraParams:     map[string]string{"ttl": "86400", "reauth": "true"},
				},
			},
		},
		"when --listen-port is set, it should convert the port to address": {
			args: []string{
				"--listen-port", "10080",
				"--listen-port", "20080",
			},
			want: authentication.GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:           []string{"127.0.0.1:10080", "127.0.0.1:20080"},
					AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
					RedirectURLHostname:   "localhost",
				},
			},
		},
		"when --listen-port is set, it should ignore --listen-address flags": {
			args: []string{
				"--listen-port", "10080",
				"--listen-port", "20080",
				"--listen-address", "127.0.0.1:30080",
				"--listen-address", "127.0.0.1:40080",
			},
			want: authentication.GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:           []string{"127.0.0.1:10080", "127.0.0.1:20080"},
					AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
					RedirectURLHostname:   "localhost",
				},
			},
		},
		"GrantType=authcode-keyboard": {
			args: []string{
				"--grant-type", "authcode-keyboard",
			},
			want: authentication.GrantOptionSet{
				AuthCodeKeyboardOption: &authcode.KeyboardOption{},
			},
		},
		"GrantType=password": {
			args: []string{
				"--grant-type", "password",
				"--listen-address", "127.0.0.1:10080",
				"--listen-address", "127.0.0.1:20080",
				"--username", "USER",
				"--password", "PASS",
			},
			want: authentication.GrantOptionSet{
				ROPCOption: &ropc.Option{
					Username: "USER",
					Password: "PASS",
				},
			},
		},
		"GrantType=auto": {
			args: []string{
				"--listen-address", "127.0.0.1:10080",
				"--listen-address", "127.0.0.1:20080",
				"--username", "USER",
				"--password", "PASS",
			},
			want: authentication.GrantOptionSet{
				ROPCOption: &ropc.Option{
					Username: "USER",
					Password: "PASS",
				},
			},
		},
	}

	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			var o authenticationOptions
			f := pflag.NewFlagSet("", pflag.ContinueOnError)
			o.addFlags(f)
			if err := f.Parse(c.args); err != nil {
				t.Fatalf("Parse error: %s", err)
			}
			got, err := o.grantOptionSet()
			if err != nil {
				t.Fatalf("grantOptionSet error: %s", err)
			}
			if diff := cmp.Diff(c.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
