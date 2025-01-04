// Package credentialplugin provides the use-cases for running as a client-go credentials plugin.
//
// See https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
package credentialplugin

import (
	"context"
	"fmt"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/credentialplugin"
	credentialpluginreader "github.com/int128/kubelogin/pkg/credentialplugin/reader"
	credentialpluginwriter "github.com/int128/kubelogin/pkg/credentialplugin/writer"
	"github.com/int128/kubelogin/pkg/infrastructure/clock"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/int128/kubelogin/pkg/tokencache/repository"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
)

var Set = wire.NewSet(
	wire.Struct(new(GetToken), "*"),
	wire.Bind(new(Interface), new(*GetToken)),
)

type Interface interface {
	Do(ctx context.Context, in Input) error
}

// Input represents an input DTO of the GetToken use-case.
type Input struct {
	Provider          oidc.Provider
	TokenCacheDir     string
	TokenCacheStorage tokencache.Storage
	GrantOptionSet    authentication.GrantOptionSet
	TLSClientConfig   tlsclientconfig.Config
	ForceRefresh      bool
}

type GetToken struct {
	Authentication         authentication.Interface
	TokenCacheRepository   repository.Interface
	CredentialPluginReader credentialpluginreader.Interface
	CredentialPluginWriter credentialpluginwriter.Interface
	Logger                 logger.Interface
	Clock                  clock.Interface
}

func (u *GetToken) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("WARNING: log may contain your secrets such as token or password")

	credentialPluginInput, err := u.CredentialPluginReader.Read()
	if err != nil {
		return fmt.Errorf("could not read the input of credential plugin: %w", err)
	}
	u.Logger.V(1).Infof("credential plugin is called with apiVersion: %s", credentialPluginInput.ClientAuthenticationAPIVersion)

	u.Logger.V(1).Infof("finding a token from cache directory %s", in.TokenCacheDir)
	tokenCacheKey := tokencache.Key{
		Provider:        in.Provider,
		TLSClientConfig: in.TLSClientConfig,
	}
	if in.GrantOptionSet.ROPCOption != nil {
		tokenCacheKey.Username = in.GrantOptionSet.ROPCOption.Username
	}

	u.Logger.V(1).Infof("acquiring the lock of token cache")
	lock, err := u.TokenCacheRepository.Lock(in.TokenCacheDir, in.TokenCacheStorage, tokenCacheKey)
	if err != nil {
		return fmt.Errorf("could not lock the token cache: %w", err)
	}
	defer func() {
		u.Logger.V(1).Infof("releasing the lock of token cache")
		if err := lock.Close(); err != nil {
			u.Logger.Printf("could not unlock the token cache: %s", err)
		}
	}()

	cachedTokenSet, err := u.TokenCacheRepository.FindByKey(in.TokenCacheDir, in.TokenCacheStorage, tokenCacheKey)
	if err != nil {
		u.Logger.V(1).Infof("could not find a token cache: %s", err)
	}
	if cachedTokenSet != nil {
		if in.ForceRefresh {
			u.Logger.V(1).Infof("forcing refresh of the existing token")
		} else {
			u.Logger.V(1).Infof("checking expiration of the existing token")
			// Skip verification of the token to reduce time of a discovery request.
			// Here it trusts the signature and claims and checks only expiration,
			// because the token has been verified before caching.
			claims, err := cachedTokenSet.DecodeWithoutVerify()
			if err != nil {
				return fmt.Errorf("invalid token cache (you may need to remove): %w", err)
			}
			if !claims.IsExpired(u.Clock) {
				u.Logger.V(1).Infof("you already have a valid token until %s", claims.Expiry)
				out := credentialplugin.Output{
					Token:                          cachedTokenSet.IDToken,
					Expiry:                         claims.Expiry,
					ClientAuthenticationAPIVersion: credentialPluginInput.ClientAuthenticationAPIVersion,
				}
				if err := u.CredentialPluginWriter.Write(out); err != nil {
					return fmt.Errorf("could not write the token to client-go: %w", err)
				}
				return nil
			}
			u.Logger.V(1).Infof("you have an expired token at %s", claims.Expiry)
		}
	}

	authenticationInput := authentication.Input{
		Provider:        in.Provider,
		GrantOptionSet:  in.GrantOptionSet,
		CachedTokenSet:  cachedTokenSet,
		TLSClientConfig: in.TLSClientConfig,
		ForceRefresh:    in.ForceRefresh,
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
	u.Logger.V(1).Infof("you got a valid token until %s", idTokenClaims.Expiry)
	if err := u.TokenCacheRepository.Save(in.TokenCacheDir, in.TokenCacheStorage, tokenCacheKey, authenticationOutput.TokenSet); err != nil {
		return fmt.Errorf("could not write the token cache: %w", err)
	}
	u.Logger.V(1).Infof("writing the token to client-go")
	out := credentialplugin.Output{
		Token:                          authenticationOutput.TokenSet.IDToken,
		Expiry:                         idTokenClaims.Expiry,
		ClientAuthenticationAPIVersion: credentialPluginInput.ClientAuthenticationAPIVersion,
	}
	if err := u.CredentialPluginWriter.Write(out); err != nil {
		return fmt.Errorf("could not write the token to client-go: %w", err)
	}
	return nil
}
