package standalone

import (
	"context"
	"fmt"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/kubeconfig"
	"github.com/int128/kubelogin/pkg/kubeconfig/loader"
	"github.com/int128/kubelogin/pkg/kubeconfig/writer"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
)

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
	GrantOptionSet     authentication.GrantOptionSet
	TLSClientConfig    tlsclientconfig.Config
}

const oidcConfigErrorMessage = `No configuration found.
You need to set up the OIDC provider, role binding, Kubernetes API server and kubeconfig.
To show the setup instruction:

	kubectl oidc-login setup

See https://github.com/int128/kubelogin for more.
`

// Standalone provides the use case of explicit login.
//
// If the current auth provider is not oidc, show the error.
// If the kubeconfig has a valid token, do nothing.
// Otherwise, update the kubeconfig.
//
type Standalone struct {
	Authentication   authentication.Interface
	KubeconfigLoader loader.Interface
	KubeconfigWriter writer.Interface
	Logger           logger.Interface
}

func (u *Standalone) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("WARNING: log may contain your secrets such as token or password")

	authProvider, err := u.KubeconfigLoader.GetCurrentAuthProvider(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)
	if err != nil {
		u.Logger.Printf(oidcConfigErrorMessage)
		return fmt.Errorf("could not find the current authentication provider: %w", err)
	}
	u.Logger.V(1).Infof("using the authentication provider of the user %s", authProvider.UserName)
	u.Logger.V(1).Infof("a token will be written to %s", authProvider.LocationOfOrigin)
	if authProvider.IDPCertificateAuthority != "" {
		u.Logger.V(1).Infof("using the certificate %s", authProvider.IDPCertificateAuthority)
		in.TLSClientConfig.CACertFilename = append(in.TLSClientConfig.CACertFilename, authProvider.IDPCertificateAuthority)
	}
	if authProvider.IDPCertificateAuthorityData != "" {
		u.Logger.V(1).Infof("using the certificate in %s", authProvider.LocationOfOrigin)
		in.TLSClientConfig.CACertData = append(in.TLSClientConfig.CACertData, authProvider.IDPCertificateAuthorityData)
	}
	var cachedTokenSet *oidc.TokenSet
	if authProvider.IDToken != "" {
		cachedTokenSet = &oidc.TokenSet{
			IDToken:      authProvider.IDToken,
			RefreshToken: authProvider.RefreshToken,
		}
	}

	authenticationInput := authentication.Input{
		Provider: oidc.Provider{
			IssuerURL:    authProvider.IDPIssuerURL,
			ClientID:     authProvider.ClientID,
			ClientSecret: authProvider.ClientSecret,
			ExtraScopes:  authProvider.ExtraScopes,
		},
		GrantOptionSet:  in.GrantOptionSet,
		CachedTokenSet:  cachedTokenSet,
		TLSClientConfig: in.TLSClientConfig,
	}
	authenticationOutput, err := u.Authentication.Do(ctx, authenticationInput)
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}

	idTokenClaims, err := authenticationOutput.TokenSet.DecodeWithoutVerify()
	if err != nil {
		return fmt.Errorf("you got an invalid token: %w", err)
	}
	u.Logger.V(1).Infof("you got a token: %s", idTokenClaims.Pretty)
	if authenticationOutput.AlreadyHasValidIDToken {
		u.Logger.Printf("You already have a valid token until %s", idTokenClaims.Expiry)
		return nil
	}

	u.Logger.Printf("You got a valid token until %s", idTokenClaims.Expiry)
	authProvider.IDToken = authenticationOutput.TokenSet.IDToken
	authProvider.RefreshToken = authenticationOutput.TokenSet.RefreshToken
	u.Logger.V(1).Infof("writing the ID token and refresh token to %s", authProvider.LocationOfOrigin)
	if err := u.KubeconfigWriter.UpdateAuthProvider(*authProvider); err != nil {
		return fmt.Errorf("could not update the kubeconfig: %w", err)
	}
	return nil
}
