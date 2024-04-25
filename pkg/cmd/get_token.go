package cmd

import (
	"errors"
	"fmt"

	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// getTokenOptions represents the options for get-token command.
type getTokenOptions struct {
	IssuerURL             string
	ClientID              string
	ClientSecret          string
	ExtraScopes           []string
	UsePKCE               bool
	UseAccessToken        bool
	TokenCacheDir         string
	tlsOptions            tlsOptions
	authenticationOptions authenticationOptions
	ForceRefresh          bool
}

func (o *getTokenOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.IssuerURL, "oidc-issuer-url", "", "Issuer URL of the provider (mandatory)")
	f.StringVar(&o.ClientID, "oidc-client-id", "", "Client ID of the provider (mandatory)")
	f.StringVar(&o.ClientSecret, "oidc-client-secret", "", "Client secret of the provider")
	f.StringSliceVar(&o.ExtraScopes, "oidc-extra-scope", nil, "Scopes to request to the provider")
	f.BoolVar(&o.UsePKCE, "oidc-use-pkce", false, "Force PKCE usage")
	f.BoolVar(&o.UseAccessToken, "oidc-use-access-token", false, "Instead of using the id_token, use the access_token to authenticate to Kubernetes")
	f.StringVar(&o.TokenCacheDir, "token-cache-dir", defaultTokenCacheDir, "Path to a directory for token cache")
	f.BoolVar(&o.ForceRefresh, "force-refresh", false, "If set, refresh the ID token regardless of its expiration time")
	o.tlsOptions.addFlags(f)
	o.authenticationOptions.addFlags(f)
}

func (o *getTokenOptions) expandHomedir() error {
	o.TokenCacheDir = expandHomedir(o.TokenCacheDir)
	o.authenticationOptions.expandHomedir()
	o.tlsOptions.expandHomedir()
	return nil
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
				return errors.New("--oidc-issuer-url is missing")
			}
			if o.ClientID == "" {
				return errors.New("--oidc-client-id is missing")
			}
			return nil
		},
		RunE: func(c *cobra.Command, _ []string) error {
			if err := o.expandHomedir(); err != nil {
				return err
			}
			grantOptionSet, err := o.authenticationOptions.grantOptionSet()
			if err != nil {
				return fmt.Errorf("get-token: %w", err)
			}
			in := credentialplugin.Input{
				Provider: oidc.Provider{
					IssuerURL:    o.IssuerURL,
					ClientID:     o.ClientID,
					ClientSecret: o.ClientSecret,
					UsePKCE:      o.UsePKCE,
					ExtraScopes:  o.ExtraScopes,
				},
				TokenCacheDir:   o.TokenCacheDir,
				GrantOptionSet:  grantOptionSet,
				TLSClientConfig: o.tlsOptions.tlsClientConfig(),
				ForceRefresh:    o.ForceRefresh,
				UseAccessToken:  o.UseAccessToken,
			}
			if err := cmd.GetToken.Do(c.Context(), in); err != nil {
				return fmt.Errorf("get-token: %w", err)
			}
			return nil
		},
	}
	c.Flags().SortFlags = false
	o.addFlags(c.Flags())
	return c
}
