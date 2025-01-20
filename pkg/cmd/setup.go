package cmd

import (
	"fmt"

	_ "embed"

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
	UseAccessToken        bool
	tlsOptions            tlsOptions
	pkceOptions           pkceOptions
	authenticationOptions authenticationOptions
}

func (o *setupOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.IssuerURL, "oidc-issuer-url", "", "Issuer URL of the provider")
	f.StringVar(&o.ClientID, "oidc-client-id", "", "Client ID of the provider")
	f.StringVar(&o.ClientSecret, "oidc-client-secret", "", "Client secret of the provider")
	f.StringSliceVar(&o.ExtraScopes, "oidc-extra-scope", nil, "Scopes to request to the provider")
	f.BoolVar(&o.UseAccessToken, "oidc-use-access-token", false, "Instead of using the id_token, use the access_token to authenticate to Kubernetes")
	o.tlsOptions.addFlags(f)
	o.pkceOptions.addFlags(f)
	o.authenticationOptions.addFlags(f)
}

type Setup struct {
	Setup setup.Interface
}

//go:embed setup.md
var setupLongDescription string

func (cmd *Setup) New() *cobra.Command {
	var o setupOptions
	c := &cobra.Command{
		Use:   "setup",
		Short: "Show the setup instruction",
		Long:  setupLongDescription,
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			var changedFlags []string
			c.Flags().VisitAll(func(f *pflag.Flag) {
				if !f.Changed {
					return
				}
				if sliceValue, ok := f.Value.(pflag.SliceValue); ok {
					for _, v := range sliceValue.GetSlice() {
						changedFlags = append(changedFlags, fmt.Sprintf("--%s=%s", f.Name, v))
					}
					return
				}
				changedFlags = append(changedFlags, fmt.Sprintf("--%s=%s", f.Name, f.Value))
			})

			grantOptionSet, err := o.authenticationOptions.grantOptionSet()
			if err != nil {
				return fmt.Errorf("setup: %w", err)
			}
			pkceMethod, err := o.pkceOptions.pkceMethod()
			if err != nil {
				return fmt.Errorf("setup: %w", err)
			}
			in := setup.Input{
				IssuerURL:       o.IssuerURL,
				ClientID:        o.ClientID,
				ClientSecret:    o.ClientSecret,
				ExtraScopes:     o.ExtraScopes,
				UseAccessToken:  o.UseAccessToken,
				PKCEMethod:      pkceMethod,
				GrantOptionSet:  grantOptionSet,
				TLSClientConfig: o.tlsOptions.tlsClientConfig(),
				ChangedFlags:    changedFlags,
			}
			if in.IssuerURL == "" || in.ClientID == "" {
				return c.Help()
			}
			if err := cmd.Setup.Do(c.Context(), in); err != nil {
				return fmt.Errorf("setup: %w", err)
			}
			return nil
		},
	}
	c.Flags().SortFlags = false
	o.addFlags(c.Flags())
	return c
}
