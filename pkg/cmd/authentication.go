package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/devicecode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/int128/kubelogin/pkg/usecases/authentication/tokenexchange"
)

type authenticationOptions struct {
	GrantType                  string
	ListenAddress              []string
	AuthenticationTimeoutSec   int
	SkipOpenBrowser            bool
	BrowserCommand             string
	LocalServerCertFile        string
	LocalServerKeyFile         string
	OpenURLAfterAuthentication string
	AuthRequestExtraParams     map[string]string
	Username                   string
	Password                   string

	TokenExchangeResource           []string
	TokenExchangeAudience           []string
	TokenExchangeRequestedTokenType string
	TokenExchangeSubjectToken       string
	TokenExchangeSubjectTokenType   string
	TokenExchangeActorToken         string
	TokenExchangeActorTokenType     string
}

var allGrantType = strings.Join([]string{
	"auto",
	"authcode",
	"authcode-keyboard",
	"password",
	"device-code",
	"client-credentials",
	"token-exchange",
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
	f.StringToStringVar(&o.AuthRequestExtraParams, "oidc-auth-request-extra-params", nil, "[authcode, authcode-keyboard, client-credentials, token-exchange] Extra query parameters to send with an authentication request")
	f.StringVar(&o.Username, "username", "", "[password] Username for resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "[password] Password for resource owner password credentials grant")
	f.StringSliceVar(&o.TokenExchangeResource, "token-exchange-resource", []string{}, "[token-exchange] a URI for the target resource the client intends to use")
	f.StringSliceVar(&o.TokenExchangeAudience, "token-exchange-audience", []string{}, "[token-exchange] the audience the client intends to use")
	f.StringVar(&o.TokenExchangeRequestedTokenType, "token-exchange-requested-token-type", "", "[token-exchange] return type desired in response, e.g. id-token or access-token")
	f.StringVar(&o.TokenExchangeSubjectToken, "token-exchange-subject-token", "", "[token-exchange] the token to exchange (required)")
	f.StringVar(&o.TokenExchangeSubjectTokenType, "token-exchange-subject-token-type", client.AccessTokenType, "[token-exchange] the type of token provided, e.g. id-token or access-token (required)")
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
			BindAddress:                o.ListenAddress,
			SkipOpenBrowser:            o.SkipOpenBrowser,
			BrowserCommand:             o.BrowserCommand,
			AuthenticationTimeout:      time.Duration(o.AuthenticationTimeoutSec) * time.Second,
			LocalServerCertFile:        o.LocalServerCertFile,
			LocalServerKeyFile:         o.LocalServerKeyFile,
			OpenURLAfterAuthentication: o.OpenURLAfterAuthentication,
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
	case o.GrantType == "client-credentials":
		endpointparams := make(map[string][]string, len(o.AuthRequestExtraParams))
		for k, v := range o.AuthRequestExtraParams {
			endpointparams[k] = []string{v}
		}
		s.ClientCredentialsOption = &client.GetTokenByClientCredentialsInput{EndpointParams: endpointparams}
	case o.GrantType == "token-exchange":
		// TODO(vdbe): implement this
		s.TokenExchangeOption = &tokenexchange.TokenExchangeOption{}
		err = fmt.Errorf("grant-type %s is not implemented", allGrantType)
	default:
		err = fmt.Errorf("grant-type must be one of (%s)", allGrantType)
	}
	return
}
