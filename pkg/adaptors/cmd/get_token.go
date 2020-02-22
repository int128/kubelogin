package cmd

import (
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

// getTokenOptions represents the options for get-token command.
type getTokenOptions struct {
	IssuerURL             string
	ClientID              string
	ClientSecret          string
	ExtraScopes           []string
	CACertFilename        string
	CACertData            string
	SkipTLSVerify         bool
	TokenCacheDir         string
	authenticationOptions authenticationOptions
}

func (o *getTokenOptions) register(f *pflag.FlagSet) {
	f.SortFlags = false
	f.StringVar(&o.IssuerURL, "oidc-issuer-url", "", "Issuer URL of the provider (mandatory)")
	f.StringVar(&o.ClientID, "oidc-client-id", "", "Client ID of the provider (mandatory)")
	f.StringVar(&o.ClientSecret, "oidc-client-secret", "", "Client secret of the provider")
	f.StringSliceVar(&o.ExtraScopes, "oidc-extra-scope", nil, "Scopes to request to the provider")
	f.StringVar(&o.CACertFilename, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.StringVar(&o.CACertData, "certificate-authority-data", "", "Base64 encoded data for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	f.StringVar(&o.TokenCacheDir, "token-cache-dir", defaultTokenCacheDir, "Path to a directory for caching tokens")
	o.authenticationOptions.register(f)
}

type GetToken struct {
	GetToken credentialplugin.Interface
	Logger   logger.Interface
}

func (cmd *GetToken) New() *cobra.Command {
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
		RunE: func(c *cobra.Command, _ []string) error {
			grantOptionSet, err := o.authenticationOptions.grantOptionSet()
			if err != nil {
				return xerrors.Errorf("get-token: %w", err)
			}
			in := credentialplugin.Input{
				IssuerURL:      o.IssuerURL,
				ClientID:       o.ClientID,
				ClientSecret:   o.ClientSecret,
				ExtraScopes:    o.ExtraScopes,
				CACertFilename: o.CACertFilename,
				CACertData:     o.CACertData,
				SkipTLSVerify:  o.SkipTLSVerify,
				TokenCacheDir:  o.TokenCacheDir,
				GrantOptionSet: grantOptionSet,
			}
			if err := cmd.GetToken.Do(c.Context(), in); err != nil {
				return xerrors.Errorf("get-token: %w", err)
			}
			return nil
		},
	}
	o.register(c.Flags())
	return c
}
