package cmd

import (
	"context"

	"github.com/int128/kubelogin/pkg/usecases/setup"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

// setupOptions represents the options for setup command.
type setupOptions struct {
	IssuerURL             string
	ClientID              string
	ClientSecret          string
	ExtraScopes           []string
	CertificateAuthority  string
	SkipTLSVerify         bool
	authenticationOptions authenticationOptions
}

func (o *setupOptions) register(f *pflag.FlagSet) {
	f.SortFlags = false
	f.StringVar(&o.IssuerURL, "oidc-issuer-url", "", "Issuer URL of the provider")
	f.StringVar(&o.ClientID, "oidc-client-id", "", "Client ID of the provider")
	f.StringVar(&o.ClientSecret, "oidc-client-secret", "", "Client secret of the provider")
	f.StringSliceVar(&o.ExtraScopes, "oidc-extra-scope", nil, "Scopes to request to the provider")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	o.authenticationOptions.register(f)
}

type Setup struct {
	Setup setup.Interface
}

func (cmd *Setup) New(ctx context.Context) *cobra.Command {
	var o setupOptions
	c := &cobra.Command{
		Use:   "setup",
		Short: "Show the setup instruction",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			authCodeOption, ropcOption := o.authenticationOptions.toUseCaseOptions()
			in := setup.Stage2Input{
				IssuerURL:      o.IssuerURL,
				ClientID:       o.ClientID,
				ClientSecret:   o.ClientSecret,
				ExtraScopes:    o.ExtraScopes,
				CACertFilename: o.CertificateAuthority,
				SkipTLSVerify:  o.SkipTLSVerify,
				AuthCodeOption: authCodeOption,
				ROPCOption:     ropcOption,
			}
			if c.Flags().Lookup("listen-port").Changed {
				in.ListenPortArgs = o.authenticationOptions.ListenPort
			}
			if in.IssuerURL == "" || in.ClientID == "" {
				cmd.Setup.DoStage1()
				return nil
			}
			if err := cmd.Setup.DoStage2(ctx, in); err != nil {
				return xerrors.Errorf("error: %w", err)
			}
			return nil
		},
	}
	o.register(c.Flags())
	return c
}
