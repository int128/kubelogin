// Package credentialplugin provides the use-cases for running as a client-go credentials plugin.
//
// See https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
package credentialplugin

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/credentialplugin"
	"github.com/int128/kubelogin/pkg/credentialplugin/writer"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/infrastructure/mutex"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/int128/kubelogin/pkg/tokencache/repository"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
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
	Provider        oidc.Provider
	TokenCacheDir   string
	GrantOptionSet  authentication.GrantOptionSet
	TLSClientConfig tlsclientconfig.Config
	ForceRefresh    bool
	UseAccessToken  bool
}

type GetToken struct {
	Authentication       authentication.Interface
	TokenCacheRepository repository.Interface
	Writer               writer.Interface
	Mutex                mutex.Interface
	Logger               logger.Interface
}

func (u *GetToken) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("WARNING: log may contain your secrets such as token or password")

	// Prevent multiple concurrent port binding using a file mutex.
	// See https://github.com/int128/kubelogin/issues/389
	bindPorts := extractBindAddressPorts(in.GrantOptionSet.AuthCodeBrowserOption)
	if bindPorts != nil {
		key := fmt.Sprintf("get-token-%s", strings.Join(bindPorts, "-"))
		u.Logger.V(1).Infof("acquiring a lock %s", key)
		lock, err := u.Mutex.Acquire(ctx, key)
		if err != nil {
			return fmt.Errorf("could not acquire a lock: %w", err)
		}
		defer func() {
			if err := u.Mutex.Release(lock); err != nil {
				u.Logger.V(1).Infof("could not release the lock: %s", err)
			}
		}()
	}

	u.Logger.V(1).Infof("finding a token from cache directory %s", in.TokenCacheDir)
	tokenCacheKey := tokencache.Key{
		IssuerURL:      in.Provider.IssuerURL,
		ClientID:       in.Provider.ClientID,
		ClientSecret:   in.Provider.ClientSecret,
		ExtraScopes:    in.Provider.ExtraScopes,
		CACertFilename: strings.Join(in.TLSClientConfig.CACertFilename, ","),
		CACertData:     strings.Join(in.TLSClientConfig.CACertData, ","),
		SkipTLSVerify:  in.TLSClientConfig.SkipTLSVerify,
	}
	if in.GrantOptionSet.ROPCOption != nil {
		tokenCacheKey.Username = in.GrantOptionSet.ROPCOption.Username
	}
	cachedTokenSet, err := u.TokenCacheRepository.FindByKey(in.TokenCacheDir, tokenCacheKey)
	if err != nil {
		u.Logger.V(1).Infof("could not find a token cache: %s", err)
	}

	authenticationInput := authentication.Input{
		Provider:        in.Provider,
		GrantOptionSet:  in.GrantOptionSet,
		CachedTokenSet:  cachedTokenSet,
		TLSClientConfig: in.TLSClientConfig,
		ForceRefresh:    in.ForceRefresh,
		UseAccessToken:  in.UseAccessToken,
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
		u.Logger.V(1).Infof("you already have a valid token until %s", idTokenClaims.Expiry)
	} else {
		u.Logger.V(1).Infof("you got a valid token until %s", idTokenClaims.Expiry)
		if err := u.TokenCacheRepository.Save(in.TokenCacheDir, tokenCacheKey, authenticationOutput.TokenSet); err != nil {
			return fmt.Errorf("could not write the token cache: %w", err)
		}
	}
	u.Logger.V(1).Infof("writing the token to client-go")
	out := credentialplugin.Output{
		Token:  authenticationOutput.TokenSet.IDToken,
		Expiry: idTokenClaims.Expiry,
	}
	if err := u.Writer.Write(out); err != nil {
		return fmt.Errorf("could not write the token to client-go: %w", err)
	}
	return nil
}

func extractBindAddressPorts(o *authcode.BrowserOption) []string {
	if o == nil {
		return nil
	}
	var ports []string
	for _, addr := range o.BindAddress {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil // invalid address
		}
		if port == "0" {
			return nil // any port
		}
		ports = append(ports, port)
	}
	return ports
}
