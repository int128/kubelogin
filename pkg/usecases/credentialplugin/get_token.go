// Package credentialplugin provides the use-cases for running as a client-go credentials plugin.
//
// See https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
package credentialplugin

import (
	"context"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/usecases"
	"golang.org/x/xerrors"
)

var Set = wire.NewSet(
	wire.Struct(new(GetToken), "*"),
	wire.Bind(new(usecases.GetToken), new(*GetToken)),
)

type GetToken struct {
	Authentication       usecases.Authentication
	TokenCacheRepository tokencache.Interface
	Interaction          credentialplugin.Interface
	Logger               logger.Interface
}

func (u *GetToken) Do(ctx context.Context, in usecases.GetTokenIn) error {
	u.Logger.V(1).Infof("WARNING: log may contain your secrets such as token or password")

	u.Logger.V(1).Infof("finding a token from cache directory %s", in.TokenCacheDir)
	cacheKey := tokencache.Key{IssuerURL: in.IssuerURL, ClientID: in.ClientID}
	cache, err := u.TokenCacheRepository.FindByKey(in.TokenCacheDir, cacheKey)
	if err != nil {
		u.Logger.V(1).Infof("could not find a token cache: %s", err)
		cache = &tokencache.TokenCache{}
	}
	out, err := u.Authentication.Do(ctx, usecases.AuthenticationIn{
		OIDCConfig: kubeconfig.OIDCConfig{
			IDPIssuerURL: in.IssuerURL,
			ClientID:     in.ClientID,
			ClientSecret: in.ClientSecret,
			ExtraScopes:  in.ExtraScopes,
			IDToken:      cache.IDToken,
			RefreshToken: cache.RefreshToken,
		},
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
	if !out.AlreadyHasValidIDToken {
		u.Logger.Printf("You got a valid token until %s", out.IDTokenExpiry)
		cache := tokencache.TokenCache{
			IDToken:      out.IDToken,
			RefreshToken: out.RefreshToken,
		}
		if err := u.TokenCacheRepository.Save(in.TokenCacheDir, cacheKey, cache); err != nil {
			return xerrors.Errorf("could not write the token cache: %w", err)
		}
	}

	u.Logger.V(1).Infof("writing the token to client-go")
	if err := u.Interaction.Write(credentialplugin.Output{Token: out.IDToken, Expiry: out.IDTokenExpiry}); err != nil {
		return xerrors.Errorf("could not write the token to client-go: %w", err)
	}
	return nil
}
