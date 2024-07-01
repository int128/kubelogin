package cmd

import (
	"fmt"

	"github.com/int128/kubelogin/pkg/usecases/setup"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// setupOptions represents the options for setup command.
type setupOptions struct {
	IssuerURL             string
	ClientID              string
	ClientSecret          string
	ExtraScopes           []string
	UsePKCE               bool
	UseAccessToken        bool
	tlsOptions            tlsOptions
	authenticationOptions authenticationOptions
}

func (o *setupOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.IssuerURL, "oidc-issuer-url", "", "Issuer URL of the provider")
	f.StringVar(&o.ClientID, "oidc-client-id", "", "Client ID of the provider")
	f.StringVar(&o.ClientSecret, "oidc-client-secret", "", "Client secret of the provider")
	f.StringSliceVar(&o.ExtraScopes, "oidc-extra-scope", nil, "Scopes to request to the provider")
	f.BoolVar(&o.UsePKCE, "oidc-use-pkce", false, "Force PKCE usage")
	f.BoolVar(&o.UseAccessToken, "oidc-use-access-token", false, "Instead of using the id_token, use the access_token to authenticate to Kubernetes")
	o.tlsOptions.addFlags(f)
	o.authenticationOptions.addFlags(f)
}

type Setup struct {
	Setup setup.Interface
}

func (cmd *Setup) New() *cobra.Command {
	var o setupOptions
	c := &cobra.Command{
		Use:   "setup",
		Short: "Show the setup instruction",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			grantOptionSet, err := o.authenticationOptions.grantOptionSet()
			if err != nil {
				return fmt.Errorf("setup: %w", err)
			}
			in := setup.Stage2Input{
				IssuerURL:       o.IssuerURL,
				ClientID:        o.ClientID,
				ClientSecret:    o.ClientSecret,
				ExtraScopes:     o.ExtraScopes,
				UsePKCE:         o.UsePKCE,
				UseAccessToken:  o.UseAccessToken,
				GrantOptionSet:  grantOptionSet,
				TLSClientConfig: o.tlsOptions.tlsClientConfig(),
			}
			if c.Flags().Lookup("listen-address").Changed {
				in.ListenAddressArgs = o.authenticationOptions.ListenAddress
			}
			if in.IssuerURL == "" || in.ClientID == "" {
				cmd.Setup.DoStage1()
				return nil
			}
			if err := cmd.Setup.DoStage2(c.Context(), in); err != nil {
				return fmt.Errorf("setup: %w", err)
			}
			return nil
		},
	}
	c.Flags().SortFlags = false
	o.addFlags(c.Flags())
	return c
}
