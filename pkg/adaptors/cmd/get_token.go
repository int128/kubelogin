package cmd

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

// getTokenOptions represents the options for get-token command.
type getTokenOptions struct {
	IssuerURL            string
	ClientID             string
	ClientSecret         string
	ExtraScopes          []string
	ListenPort           []int
	SkipOpenBrowser      bool
	Username             string
	Password             string
	CertificateAuthority string
	SkipTLSVerify        bool
	TokenCacheDir        string
}

func (o *getTokenOptions) register(f *pflag.FlagSet) {
	f.SortFlags = false
	f.StringVar(&o.IssuerURL, "oidc-issuer-url", "", "Issuer URL of the provider (mandatory)")
	f.StringVar(&o.ClientID, "oidc-client-id", "", "Client ID of the provider (mandatory)")
	f.StringVar(&o.ClientSecret, "oidc-client-secret", "", "Client secret of the provider")
	f.StringSliceVar(&o.ExtraScopes, "oidc-extra-scope", nil, "Scopes to request to the provider")
	f.IntSliceVar(&o.ListenPort, "listen-port", defaultListenPort, "Port to bind to the local server. If multiple ports are given, it will try the ports in order")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.StringVar(&o.Username, "username", "", "If set, perform the resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "If set, use the password instead of asking it")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	f.StringVar(&o.TokenCacheDir, "token-cache-dir", defaultTokenCacheDir, "Path to a directory for caching tokens")
}

type GetToken struct {
	GetToken credentialplugin.Interface
	Logger   logger.Interface
}

func (cmd *GetToken) New(ctx context.Context) *cobra.Command {
	var o getTokenOptions
	c := &cobra.Command{
		Use:   "get-token [flags]",
		Short: "Run as a kubectl credential plugin",
		Args: func(c *cobra.Command, args []string) error {
			if err := cobra.NoArgs(c, args); err != nil {
				return err
			}
			if o.IssuerURL == "" {
				return xerrors.New("--oidc-issuer-url is missing")
			}
			if o.ClientID == "" {
				return xerrors.New("--oidc-client-id is missing")
			}
			return nil
		},
		RunE: func(*cobra.Command, []string) error {
			in := credentialplugin.Input{
				IssuerURL:       o.IssuerURL,
				ClientID:        o.ClientID,
				ClientSecret:    o.ClientSecret,
				ExtraScopes:     o.ExtraScopes,
				CACertFilename:  o.CertificateAuthority,
				SkipTLSVerify:   o.SkipTLSVerify,
				BindAddress:     translateListenPortToBindAddress(o.ListenPort),
				SkipOpenBrowser: o.SkipOpenBrowser,
				Username:        o.Username,
				Password:        o.Password,
				TokenCacheDir:   o.TokenCacheDir,
			}
			if err := cmd.GetToken.Do(ctx, in); err != nil {
				return xerrors.Errorf("error: %w", err)
			}
			return nil
		},
	}
	o.register(c.Flags())
	return c
}
