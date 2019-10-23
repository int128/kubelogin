package standalone

import (
	"context"
	"strings"
	"text/template"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/usecases/auth"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_standalone/mock_standalone.go github.com/int128/kubelogin/pkg/usecases/standalone Interface

// Set provides the use-case.
var Set = wire.NewSet(
	wire.Struct(new(Standalone), "*"),
	wire.Bind(new(Interface), new(*Standalone)),
)

type Interface interface {
	Do(ctx context.Context, in Input) error
}

// Input represents an input DTO of the use-case.
type Input struct {
	KubeconfigFilename string                 // Default to the environment variable or global config as kubectl
	KubeconfigContext  kubeconfig.ContextName // Default to the current context but ignored if KubeconfigUser is set
	KubeconfigUser     kubeconfig.UserName    // Default to the user of the context
	SkipOpenBrowser    bool
	ListenPort         []int
	Username           string // If set, perform the resource owner password credentials grant
	Password           string // If empty, read a password using Env.ReadPassword()
	CACertFilename     string // If set, use the CA cert
	SkipTLSVerify      bool
}

const oidcConfigErrorMessage = `You need to set up the kubeconfig for OpenID Connect authentication.
See https://github.com/int128/kubelogin for more.
`

// Standalone provides the use case of explicit login.
//
// If the current auth provider is not oidc, show the error.
// If the kubeconfig has a valid token, do nothing.
// Otherwise, update the kubeconfig.
//
type Standalone struct {
	Authentication auth.Interface
	Kubeconfig     kubeconfig.Interface
	Logger         logger.Interface
}

func (u *Standalone) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("WARNING: log may contain your secrets such as token or password")

	authProvider, err := u.Kubeconfig.GetCurrentAuthProvider(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)
	if err != nil {
		u.Logger.Printf(oidcConfigErrorMessage)
		return xerrors.Errorf("could not find the current authentication provider: %w", err)
	}
	if err := u.showDeprecation(in, authProvider); err != nil {
		return xerrors.Errorf("could not show deprecation message: %w", err)
	}
	u.Logger.V(1).Infof("using the authentication provider of the user %s", authProvider.UserName)
	u.Logger.V(1).Infof("a token will be written to %s", authProvider.LocationOfOrigin)

	out, err := u.Authentication.Do(ctx, auth.Input{
		OIDCConfig:      authProvider.OIDCConfig,
		SkipOpenBrowser: in.SkipOpenBrowser,
		ListenPort:      in.ListenPort,
		Username:        in.Username,
		Password:        in.Password,
		CACertFilename:  in.CACertFilename,
		SkipTLSVerify:   in.SkipTLSVerify,
	})
	if err != nil {
		return xerrors.Errorf("error while authentication: %w", err)
	}
	for k, v := range out.IDTokenClaims {
		u.Logger.V(1).Infof("the ID token has the claim: %s=%v", k, v)
	}
	if out.AlreadyHasValidIDToken {
		u.Logger.Printf("You already have a valid token until %s", out.IDTokenExpiry)
		return nil
	}

	u.Logger.Printf("You got a valid token until %s", out.IDTokenExpiry)
	authProvider.OIDCConfig.IDToken = out.IDToken
	authProvider.OIDCConfig.RefreshToken = out.RefreshToken
	u.Logger.V(1).Infof("writing the ID token and refresh token to %s", authProvider.LocationOfOrigin)
	if err := u.Kubeconfig.UpdateAuthProvider(authProvider); err != nil {
		return xerrors.Errorf("could not write the token to the kubeconfig: %w", err)
	}
	return nil
}

var deprecationTpl = template.Must(template.New("").Parse(
	`IMPORTANT NOTICE:
The credential plugin mode is available since v1.14.0.
Kubectl will automatically run kubelogin and you do not need to run kubelogin explicitly.

You can switch to the credential plugin mode by setting the following user to
{{ .Kubeconfig }}.
---
users:
- name: oidc
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl
      args:
      - oidc-login
      - get-token
{{- range .Args }}
      - {{ . }}
{{- end }}
---
See https://github.com/int128/kubelogin for more.

`))

type deprecationVars struct {
	Kubeconfig string
	Args       []string
}

func (u *Standalone) showDeprecation(in Input, p *kubeconfig.AuthProvider) error {
	var args []string
	args = append(args, "--oidc-issuer-url="+p.OIDCConfig.IDPIssuerURL)
	args = append(args, "--oidc-client-id="+p.OIDCConfig.ClientID)
	if p.OIDCConfig.ClientSecret != "" {
		args = append(args, "--oidc-client-secret="+p.OIDCConfig.ClientSecret)
	}
	for _, extraScope := range p.OIDCConfig.ExtraScopes {
		args = append(args, "--oidc-extra-scope="+extraScope)
	}
	if p.OIDCConfig.IDPCertificateAuthority != "" {
		args = append(args, "--certificate-authority="+p.OIDCConfig.IDPCertificateAuthority)
	}
	if in.CACertFilename != "" {
		args = append(args, "--certificate-authority="+in.CACertFilename)
	}
	if in.Username != "" {
		args = append(args, "--username="+in.Username)
	}

	v := deprecationVars{
		Kubeconfig: p.LocationOfOrigin,
		Args:       args,
	}
	var b strings.Builder
	if err := deprecationTpl.Execute(&b, &v); err != nil {
		return xerrors.Errorf("could not render the template: %w", err)
	}
	u.Logger.Printf("%s", b.String())
	return nil
}
