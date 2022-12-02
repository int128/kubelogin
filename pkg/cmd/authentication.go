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

type authenticationOptions struct {
	GrantType                  string
	ListenAddress              []string
	ListenPort                 []int // deprecated
	AuthenticationTimeoutSec   int
	SkipOpenBrowser            bool
	BrowserCommand             string
	LocalServerCertFile        string
	LocalServerKeyFile         string
	OpenURLAfterAuthentication string
	RedirectURLHostname        string
	AuthRequestExtraParams     map[string]string
	Username                   string
	Password                   string
}

// determineListenAddress returns the addresses from the flags.
// Note that --listen-address is always given due to the default value.
// If --listen-port is not set, it returns --listen-address.
// If --listen-port is set, it returns the strings of --listen-port.
func (o *authenticationOptions) determineListenAddress() []string {
	if len(o.ListenPort) == 0 {
		return o.ListenAddress
	}
	var a []string
	for _, p := range o.ListenPort {
		a = append(a, fmt.Sprintf("127.0.0.1:%d", p))
	}
	return a
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
	//TODO: remove the deprecated flag
	f.IntSliceVar(&o.ListenPort, "listen-port", nil, "[authcode] deprecated: port to bind to the local server")
	if err := f.MarkDeprecated("listen-port", "use --listen-address instead"); err != nil {
		panic(err)
	}
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "[authcode] Do not open the browser automatically")
	f.StringVar(&o.BrowserCommand, "browser-command", "", "[authcode] Command to open the browser")
	f.IntVar(&o.AuthenticationTimeoutSec, "authentication-timeout-sec", defaultAuthenticationTimeoutSec, "[authcode] Timeout of authentication in seconds")
	f.StringVar(&o.LocalServerCertFile, "local-server-cert", "", "[authcode] Certificate path for the local server")
	f.StringVar(&o.LocalServerKeyFile, "local-server-key", "", "[authcode] Certificate key path for the local server")
	f.StringVar(&o.OpenURLAfterAuthentication, "open-url-after-authentication", "", "[authcode] If set, open the URL in the browser after authentication")
	f.StringVar(&o.RedirectURLHostname, "oidc-redirect-url-hostname", "localhost", "[authcode] Hostname of the redirect URL")
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
			BindAddress:                o.determineListenAddress(),
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
