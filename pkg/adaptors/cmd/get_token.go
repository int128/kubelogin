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
	TokenCacheDir         string
	tlsOptions            tlsOptions
	authenticationOptions authenticationOptions
}

func (o *getTokenOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.IssuerURL, "oidc-issuer-url", "", "Issuer URL of the provider (mandatory)")
	f.StringVar(&o.ClientID, "oidc-client-id", "", "Client ID of the provider (mandatory)")
	f.StringVar(&o.ClientSecret, "oidc-client-secret", "", "Client secret of the provider")
	f.StringSliceVar(&o.ExtraScopes, "oidc-extra-scope", nil, "Scopes to request to the provider")
	f.StringVar(&o.TokenCacheDir, "token-cache-dir", defaultTokenCacheDir, "Path to a directory for token cache")
	o.tlsOptions.addFlags(f)
	o.authenticationOptions.addFlags(f)
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
				CACertFilename: o.tlsOptions.CACertFilename,
				CACertData:     o.tlsOptions.CACertData,
				SkipTLSVerify:  o.tlsOptions.SkipTLSVerify,
				TokenCacheDir:  o.TokenCacheDir,
				GrantOptionSet: grantOptionSet,
			}
			if err := cmd.GetToken.Do(c.Context(), in); err != nil {
				return xerrors.Errorf("get-token: %w", err)
			}
			return nil
		},
	}
	c.Flags().SortFlags = false
	o.addFlags(c.Flags())
	return c
}
