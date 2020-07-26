package standalone

import (
	"context"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
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
	CACertFilename     string                 // optional
	CACertData         string                 // optional
	SkipTLSVerify      bool
	GrantOptionSet     authentication.GrantOptionSet
}

const oidcConfigErrorMessage = `No configuration found.
You need to set up the OIDC provider, role binding, Kubernetes API server and kubeconfig.
To show the setup instruction:

	kubectl oidc-login setup

See https://github.com/int128/kubelogin for more.
`

const deprecationMessage = `NOTE: You can use the credential plugin mode for better user experience.
Kubectl automatically runs kubelogin and you do not need to run kubelogin explicitly.
See https://github.com/int128/kubelogin for more.
`

// Standalone provides the use case of explicit login.
//
// If the current auth provider is not oidc, show the error.
// If the kubeconfig has a valid token, do nothing.
// Otherwise, update the kubeconfig.
//
type Standalone struct {
	Authentication authentication.Interface
	Kubeconfig     kubeconfig.Interface
	NewCertPool    certpool.NewFunc
	Logger         logger.Interface
}

func (u *Standalone) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("WARNING: log may contain your secrets such as token or password")

	authProvider, err := u.Kubeconfig.GetCurrentAuthProvider(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)
	if err != nil {
		u.Logger.Printf(oidcConfigErrorMessage)
		return xerrors.Errorf("could not find the current authentication provider: %w", err)
	}
	u.Logger.Printf(deprecationMessage)
	u.Logger.V(1).Infof("using the authentication provider of the user %s", authProvider.UserName)
	u.Logger.V(1).Infof("a token will be written to %s", authProvider.LocationOfOrigin)
	certPool := u.NewCertPool()
	if authProvider.IDPCertificateAuthority != "" {
		if err := certPool.AddFile(authProvider.IDPCertificateAuthority); err != nil {
			return xerrors.Errorf("could not load the certificate of idp-certificate-authority: %w", err)
		}
	}
	if authProvider.IDPCertificateAuthorityData != "" {
		if err := certPool.AddBase64Encoded(authProvider.IDPCertificateAuthorityData); err != nil {
			return xerrors.Errorf("could not load the certificate of idp-certificate-authority-data: %w", err)
		}
	}
	if in.CACertFilename != "" {
		if err := certPool.AddFile(in.CACertFilename); err != nil {
			return xerrors.Errorf("could not load the certificate file: %w", err)
		}
	}
	if in.CACertData != "" {
		if err := certPool.AddBase64Encoded(in.CACertData); err != nil {
			return xerrors.Errorf("could not load the certificate data: %w", err)
		}
	}
	out, err := u.Authentication.Do(ctx, authentication.Input{
		IssuerURL:      authProvider.IDPIssuerURL,
		ClientID:       authProvider.ClientID,
		ClientSecret:   authProvider.ClientSecret,
		ExtraScopes:    authProvider.ExtraScopes,
		CertPool:       certPool,
		SkipTLSVerify:  in.SkipTLSVerify,
		IDToken:        authProvider.IDToken,
		RefreshToken:   authProvider.RefreshToken,
		GrantOptionSet: in.GrantOptionSet,
	})
	if err != nil {
		return xerrors.Errorf("authentication error: %w", err)
	}
	u.Logger.V(1).Infof("you got a token: %s", out.IDTokenClaims.Pretty)
	if out.AlreadyHasValidIDToken {
		u.Logger.Printf("You already have a valid token until %s", out.IDTokenClaims.Expiry)
		return nil
	}

	u.Logger.Printf("You got a valid token until %s", out.IDTokenClaims.Expiry)
	authProvider.IDToken = out.IDToken
	authProvider.RefreshToken = out.RefreshToken
	u.Logger.V(1).Infof("writing the ID token and refresh token to %s", authProvider.LocationOfOrigin)
	if err := u.Kubeconfig.UpdateAuthProvider(authProvider); err != nil {
		return xerrors.Errorf("could not update the kubeconfig: %w", err)
	}
	return nil
}
