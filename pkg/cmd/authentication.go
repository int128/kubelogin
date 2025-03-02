package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/devicecode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/spf13/pflag"
)

const oobRedirectURI = "urn:ietf:wg:oauth:2.0:oob"

type authenticationOptions struct {
	GrantType                   string
	ListenAddress               []string
	AuthenticationTimeoutSec    int
	SkipOpenBrowser             bool
	BrowserCommand              string
	LocalServerCertFile         string
	LocalServerKeyFile          string
	OpenURLAfterAuthentication  string
	RedirectURLHostname         string
	RedirectURLAuthCodeKeyboard string
	AuthRequestExtraParams      map[string]string
	Username                    string
	Password                    string
}

var allGrantType = strings.Join([]string{
	"auto",
	"authcode",
	"authcode-keyboard",
	"password",
	"device-code",
}, "|")

func (o *authenticationOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.GrantType, "grant-type", "auto", fmt.Sprintf("Authorization grant type to use. One of (%s)", allGrantType))
	f.StringSliceVar(&o.ListenAddress, "listen-address", defaultListenAddress, "[authcode] Address to bind to the local server. If multiple addresses are set, it will try binding in order")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "[authcode] Do not open the browser automatically")
	f.StringVar(&o.BrowserCommand, "browser-command", "", "[authcode] Command to open the browser")
	f.IntVar(&o.AuthenticationTimeoutSec, "authentication-timeout-sec", defaultAuthenticationTimeoutSec, "[authcode] Timeout of authentication in seconds")
	f.StringVar(&o.LocalServerCertFile, "local-server-cert", "", "[authcode] Certificate path for the local server")
	f.StringVar(&o.LocalServerKeyFile, "local-server-key", "", "[authcode] Certificate key path for the local server")
	f.StringVar(&o.OpenURLAfterAuthentication, "open-url-after-authentication", "", "[authcode] If set, open the URL in the browser after authentication")
	f.StringVar(&o.RedirectURLHostname, "oidc-redirect-url-hostname", "localhost", "[authcode] Hostname of the redirect URL")
	f.StringVar(&o.RedirectURLAuthCodeKeyboard, "oidc-redirect-url-authcode-keyboard", oobRedirectURI, "[authcode-keyboard] Redirect URL")
	f.StringToStringVar(&o.AuthRequestExtraParams, "oidc-auth-request-extra-params", nil, "[authcode, authcode-keyboard] Extra query parameters to send with an authentication request")
	f.StringVar(&o.Username, "username", "", "[password] Username for resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "[password] Password for resource owner password credentials grant")
}

func (o *authenticationOptions) expandHomedir() {
	o.LocalServerCertFile = expandHomedir(o.LocalServerCertFile)
	o.LocalServerKeyFile = expandHomedir(o.LocalServerKeyFile)
}

func (o *authenticationOptions) grantOptionSet() (s authentication.GrantOptionSet, err error) {
	switch {
	case o.GrantType == "authcode" || (o.GrantType == "auto" && o.Username == ""):
		s.AuthCodeBrowserOption = &authcode.BrowserOption{
			BindAddress:                o.ListenAddress,
			SkipOpenBrowser:            o.SkipOpenBrowser,
			BrowserCommand:             o.BrowserCommand,
			AuthenticationTimeout:      time.Duration(o.AuthenticationTimeoutSec) * time.Second,
			LocalServerCertFile:        o.LocalServerCertFile,
			LocalServerKeyFile:         o.LocalServerKeyFile,
			OpenURLAfterAuthentication: o.OpenURLAfterAuthentication,
			RedirectURLHostname:        o.RedirectURLHostname,
			AuthRequestExtraParams:     o.AuthRequestExtraParams,
		}
	case o.GrantType == "authcode-keyboard":
		s.AuthCodeKeyboardOption = &authcode.KeyboardOption{
			AuthRequestExtraParams: o.AuthRequestExtraParams,
			RedirectURL:            o.RedirectURLAuthCodeKeyboard,
		}
	case o.GrantType == "password" || (o.GrantType == "auto" && o.Username != ""):
		s.ROPCOption = &ropc.Option{
			Username: o.Username,
			Password: o.Password,
		}
	case o.GrantType == "device-code":
		s.DeviceCodeOption = &devicecode.Option{
			SkipOpenBrowser: o.SkipOpenBrowser,
			BrowserCommand:  o.BrowserCommand,
		}
	default:
		err = fmt.Errorf("grant-type must be one of (%s)", allGrantType)
	}
	return
}
