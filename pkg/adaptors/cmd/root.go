package cmd

import (
	"fmt"
	"strings"

	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

const longDescription = `Login to the OpenID Connect provider.

You need to set up the OIDC provider, role binding, Kubernetes API server and kubeconfig.
Run the following command to show the setup instruction:

	kubectl oidc-login setup

See https://github.com/int128/kubelogin for more.
`

// rootOptions represents the options for the root command.
type rootOptions struct {
	Kubeconfig            string
	Context               string
	User                  string
	CertificateAuthority  string
	SkipTLSVerify         bool
	authenticationOptions authenticationOptions
}

func (o *rootOptions) register(f *pflag.FlagSet) {
	f.SortFlags = false
	f.StringVar(&o.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")
	f.StringVar(&o.Context, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.User, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	o.authenticationOptions.register(f)
}

type authenticationOptions struct {
	GrantType              string
	ListenAddress          []string
	ListenPort             []int // deprecated
	SkipOpenBrowser        bool
	RedirectURLHostname    string
	AuthRequestExtraParams map[string]string
	Username               string
	Password               string
	LocalServerSuccessHTML string
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
}, "|")

func (o *authenticationOptions) register(f *pflag.FlagSet) {
	f.StringVar(&o.GrantType, "grant-type", "auto", fmt.Sprintf("The authorization grant type to use. One of (%s)", allGrantType))
	f.StringSliceVar(&o.ListenAddress, "listen-address", defaultListenAddress, "Address to bind to the local server. If multiple addresses are given, it will try binding in order")
	//TODO: remove the deprecated flag
	f.IntSliceVar(&o.ListenPort, "listen-port", nil, "(Deprecated: use --listen-address)")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.StringVar(&o.RedirectURLHostname, "oidc-redirect-url-hostname", "localhost", "Hostname of the redirect URL")
	f.StringToStringVar(&o.AuthRequestExtraParams, "oidc-auth-request-extra-params", nil, "Extra query parameters to send with an authentication request")
	f.StringVar(&o.Username, "username", "", "If set, perform the resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "If set, use the password instead of asking it")
	f.StringVar(&o.LocalServerSuccessHTML, "server-success-html", "", "Response HTML body on authorization completed")
}

func (o *authenticationOptions) grantOptionSet() (s authentication.GrantOptionSet, err error) {
	switch {
	case o.GrantType == "authcode" || (o.GrantType == "auto" && o.Username == ""):
		s.AuthCodeOption = &authentication.AuthCodeOption{
			BindAddress:            o.determineListenAddress(),
			SkipOpenBrowser:        o.SkipOpenBrowser,
			RedirectURLHostname:    o.RedirectURLHostname,
			AuthRequestExtraParams: o.AuthRequestExtraParams,
			LocalServerSuccessHTML: o.LocalServerSuccessHTML,
		}
	case o.GrantType == "authcode-keyboard":
		s.AuthCodeKeyboardOption = &authentication.AuthCodeKeyboardOption{
			AuthRequestExtraParams: o.AuthRequestExtraParams,
		}
	case o.GrantType == "password" || (o.GrantType == "auto" && o.Username != ""):
		s.ROPCOption = &authentication.ROPCOption{
			Username: o.Username,
			Password: o.Password,
		}
	default:
		err = xerrors.Errorf("grant-type must be one of (%s)", allGrantType)
	}
	return
}

type Root struct {
	Standalone standalone.Interface
	Logger     logger.Interface
}

func (cmd *Root) New() *cobra.Command {
	var o rootOptions
	rootCmd := &cobra.Command{
		Use:   "kubelogin",
		Short: "Login to the OpenID Connect provider",
		Long:  longDescription,
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			grantOptionSet, err := o.authenticationOptions.grantOptionSet()
			if err != nil {
				return xerrors.Errorf("invalid option: %w", err)
			}
			in := standalone.Input{
				KubeconfigFilename: o.Kubeconfig,
				KubeconfigContext:  kubeconfig.ContextName(o.Context),
				KubeconfigUser:     kubeconfig.UserName(o.User),
				CACertFilename:     o.CertificateAuthority,
				SkipTLSVerify:      o.SkipTLSVerify,
				GrantOptionSet:     grantOptionSet,
			}
			if err := cmd.Standalone.Do(c.Context(), in); err != nil {
				return xerrors.Errorf("login: %w", err)
			}
			return nil
		},
	}
	o.register(rootCmd.Flags())
	cmd.Logger.AddFlags(rootCmd.PersistentFlags())
	return rootCmd
}
