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
	"github.com/int128/kubelogin/pkg/usecases/auth"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_credentialplugin/mock_credentialplugin.go github.com/int128/kubelogin/pkg/usecases/credentialplugin Interface

var Set = wire.NewSet(
	wire.Struct(new(GetToken), "*"),
	wire.Bind(new(Interface), new(*GetToken)),
)

type Interface interface {
	Do(ctx context.Context, in Input) error
}

// Input represents an input DTO of the GetToken use-case.
type Input struct {
	IssuerURL       string
	ClientID        string
	ClientSecret    string
	ExtraScopes     []string // optional
	SkipOpenBrowser bool
	ListenPort      []int
	Username        string // If set, perform the resource owner password credentials grant
	Password        string // If empty, read a password using Env.ReadPassword()
	CACertFilename  string // If set, use the CA cert
	SkipTLSVerify   bool
	TokenCacheDir   string
}

type GetToken struct {
	Authentication       auth.Interface
	TokenCacheRepository tokencache.Interface
	Interaction          credentialplugin.Interface
	Logger               logger.Interface
}

func (u *GetToken) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("WARNING: log may contain your secrets such as token or password")

	u.Logger.V(1).Infof("finding a token from cache directory %s", in.TokenCacheDir)
	cacheKey := tokencache.Key{IssuerURL: in.IssuerURL, ClientID: in.ClientID}
	cache, err := u.TokenCacheRepository.FindByKey(in.TokenCacheDir, cacheKey)
	if err != nil {
		u.Logger.V(1).Infof("could not find a token cache: %s", err)
		cache = &tokencache.TokenCache{}
	}
	out, err := u.Authentication.Do(ctx, auth.Input{
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
