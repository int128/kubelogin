// Package credentialplugin provides the use-cases for running as a client-go credentials plugin.
//
// See https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
package credentialplugin

import (
	"context"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
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
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	ExtraScopes    []string // optional
	CACertFilename string   // If set, use the CA cert
	SkipTLSVerify  bool
	TokenCacheDir  string
	GrantOptionSet authentication.GrantOptionSet
}

type GetToken struct {
	Authentication       authentication.Interface
	TokenCacheRepository tokencache.Interface
	NewCertPool          certpool.NewFunc
	Writer               credentialpluginwriter.Interface
	Logger               logger.Interface
}

func (u *GetToken) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("WARNING: log may contain your secrets such as token or password")
	out, err := u.getTokenFromCacheOrProvider(ctx, in)
	if err != nil {
		return xerrors.Errorf("could not get a token from the cache or provider: %w", err)
	}
	u.Logger.V(1).Infof("writing the token to client-go")
	if err := u.Writer.Write(credentialpluginwriter.Output{Token: out.IDToken, Expiry: out.IDTokenClaims.Expiry}); err != nil {
		return xerrors.Errorf("could not write the token to client-go: %w", err)
	}
	return nil
}

func (u *GetToken) getTokenFromCacheOrProvider(ctx context.Context, in Input) (*authentication.Output, error) {
	u.Logger.V(1).Infof("finding a token from cache directory %s", in.TokenCacheDir)
	tokenCacheKey := tokencache.Key{
		IssuerURL:      in.IssuerURL,
		ClientID:       in.ClientID,
		ClientSecret:   in.ClientSecret,
		ExtraScopes:    in.ExtraScopes,
		CACertFilename: in.CACertFilename,
		SkipTLSVerify:  in.SkipTLSVerify,
	}
	tokenCacheValue, err := u.TokenCacheRepository.FindByKey(in.TokenCacheDir, tokenCacheKey)
	if err != nil {
		u.Logger.V(1).Infof("could not find a token cache: %s", err)
		tokenCacheValue = &tokencache.Value{}
	}
	certPool := u.NewCertPool()
	if in.CACertFilename != "" {
		if err := certPool.AddFile(in.CACertFilename); err != nil {
			return nil, xerrors.Errorf("could not load the certificate: %w", err)
		}
	}
	out, err := u.Authentication.Do(ctx, authentication.Input{
		IssuerURL:      in.IssuerURL,
		ClientID:       in.ClientID,
		ClientSecret:   in.ClientSecret,
		ExtraScopes:    in.ExtraScopes,
		CertPool:       certPool,
		SkipTLSVerify:  in.SkipTLSVerify,
		IDToken:        tokenCacheValue.IDToken,
		RefreshToken:   tokenCacheValue.RefreshToken,
		GrantOptionSet: in.GrantOptionSet,
	})
	if err != nil {
		return nil, xerrors.Errorf("error while authentication: %w", err)
	}
	for k, v := range out.IDTokenClaims.Pretty {
		u.Logger.V(1).Infof("the ID token has the claim: %s=%v", k, v)
	}
	if out.AlreadyHasValidIDToken {
		u.Logger.V(1).Infof("you already have a valid token until %s", out.IDTokenClaims.Expiry)
		return out, nil
	}

	u.Logger.V(1).Infof("you got a valid token until %s", out.IDTokenClaims.Expiry)
	newTokenCacheValue := tokencache.Value{
		IDToken:      out.IDToken,
		RefreshToken: out.RefreshToken,
	}
	if err := u.TokenCacheRepository.Save(in.TokenCacheDir, tokenCacheKey, newTokenCacheValue); err != nil {
		return nil, xerrors.Errorf("could not write the token cache: %w", err)
	}
	return out, nil
}
