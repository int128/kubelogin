package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/devicecode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/int128/kubelogin/pkg/usecases/authentication/tokenexchange"
	"github.com/spf13/pflag"
)

const oobRedirectURI = "urn:ietf:wg:oauth:2.0:oob"

type authenticationOptions struct {
	GrantType                   string
	ListenAddress               []string
	ListenPort                  []int // deprecated
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

	TokenExchangeResource           string
	TokenExchangeAudience           string
	TokenExchangeRequestedTokenType string
	TokenExchangeSubjectToken       string
	TokenExchangeSubjectTokenType   string
	TokenExchangeBasicAuth          bool
	TokenExchangeActorToken         string
	TokenExchangeActorTokenType     string
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
	"token-exchange",
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
	f.StringVar(&o.RedirectURLAuthCodeKeyboard, "oidc-redirect-url-authcode-keyboard", oobRedirectURI, "[authcode-keyboard] Redirect URL")
	f.StringToStringVar(&o.AuthRequestExtraParams, "oidc-auth-request-extra-params", nil, "[authcode, authcode-keyboard] Extra query parameters to send with an authentication request")
	f.StringVar(&o.Username, "username", "", "[password] Username for resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "[password] Password for resource owner password credentials grant")
	f.StringVar(&o.TokenExchangeResource, "token-exchange-resource", "", "[token-exchange] a URI for the target resource the client intends to use")
	f.StringVar(&o.TokenExchangeAudience, "token-exchange-audience", "", "[token-exchange] the audience the client intends to use (default: client-id)")
	f.StringVar(&o.TokenExchangeRequestedTokenType, "token-exchange-requested-token-type", "", "[token-exchange] return type desired in response, e.g. id-token or access-token")
	f.StringVar(&o.TokenExchangeSubjectToken, "token-exchange-subject-token", "", "[token-exchange] the token to exchange (required)")
	f.StringVar(&o.TokenExchangeSubjectTokenType, "token-exchange-subject-token-type", "", "[token-exchange] the type of token provided, e.g. id-token or access-token (required)")
	f.BoolVar(&o.TokenExchangeBasicAuth, "token-exchange-basic-auth", false, "[token-exchange] use basic auth for exchanging the token (default: false)")
	f.StringVar(&o.TokenExchangeActorToken, "token-exchange-actor-token", "", "[token-exchange] optional token for delegated access pattern")
	f.StringVar(&o.TokenExchangeActorTokenType, "token-exchange-actor-token-type", "", "[token-exchange] type of the actor token, e.g. id-token or access-token")
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
	case o.GrantType == "token-exchange":

		tokenExchangeOpts := tokenexchange.NewTokenExchangeOption(
			o.TokenExchangeSubjectToken,
			o.TokenExchangeSubjectTokenType,
			tokenexchange.AddAudience(o.TokenExchangeAudience),
			tokenexchange.AddRequestedTokenType(o.TokenExchangeRequestedTokenType),
			tokenexchange.AddResource(o.TokenExchangeResource),
			tokenexchange.SetBasicAuth(o.TokenExchangeBasicAuth),
			tokenexchange.AddActorToken(o.TokenExchangeActorToken, o.TokenExchangeActorTokenType),
		)

		s.TokenExchangeOption = &tokenExchangeOpts

	default:
		err = fmt.Errorf("grant-type must be one of (%s)", allGrantType)
	}
	return
}
