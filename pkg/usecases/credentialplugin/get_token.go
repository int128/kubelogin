// Package credentialplugin provides the use-cases for running as a client-go credentials plugin.
//
// See https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
package credentialplugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

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
	Provider         oidc.Provider
	ForceRefresh     bool
	TokenCacheConfig tokencache.Config
	GrantOptionSet   authentication.GrantOptionSet
	TLSClientConfig  tlsclientconfig.Config

	// Client certificate for the API server, e.g. required by an mTLS proxy in front of it.
	ExecClientCertificateFile string
	ExecClientKeyFile         string
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

	clientCert, err := loadClientCertificate(in.ExecClientCertificateFile, in.ExecClientKeyFile)
	if err != nil {
		return fmt.Errorf("could not load the client certificate: %w", err)
	}
	if clientCert != nil {
		// Otherwise the expiry would be in the past and client-go would run the plugin on every request.
		if !u.Clock.Now().Before(clientCert.notAfter) {
			return fmt.Errorf("the client certificate has expired at %s", clientCert.notAfter)
		}
		u.Logger.V(1).Infof("using the client certificate valid until %s", clientCert.notAfter)
	}

	u.Logger.V(1).Infof("finding a token cache")
	tokenCacheKey := tokencache.Key{
		Provider:               in.Provider,
		TLSClientConfig:        in.TLSClientConfig,
		AuthRequestExtraParams: in.GrantOptionSet.AuthRequestExtraParams(),
	}
	if in.GrantOptionSet.ROPCOption != nil {
		tokenCacheKey.Username = in.GrantOptionSet.ROPCOption.Username
	}

	u.Logger.V(1).Infof("acquiring the lock of token cache")
	lock, err := u.TokenCacheRepository.Lock(in.TokenCacheConfig, tokenCacheKey)
	if err != nil {
		return fmt.Errorf("could not lock the token cache: %w", err)
	}
	defer func() {
		u.Logger.V(1).Infof("releasing the lock of token cache")
		if err := lock.Close(); err != nil {
			u.Logger.Printf("could not unlock the token cache: %s", err)
		}
	}()

	cachedTokenSet, err := u.TokenCacheRepository.FindByKey(in.TokenCacheConfig, tokenCacheKey)
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
				clientCert.apply(&out)
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
	if err := u.TokenCacheRepository.Save(in.TokenCacheConfig, tokenCacheKey, authenticationOutput.TokenSet); err != nil {
		return fmt.Errorf("could not write the token cache: %w", err)
	}
	u.Logger.V(1).Infof("writing the token to client-go")
	out := credentialplugin.Output{
		Token:                          authenticationOutput.TokenSet.IDToken,
		Expiry:                         idTokenClaims.Expiry,
		ClientAuthenticationAPIVersion: credentialPluginInput.ClientAuthenticationAPIVersion,
	}
	clientCert.apply(&out)
	if err := u.CredentialPluginWriter.Write(out); err != nil {
		return fmt.Errorf("could not write the token to client-go: %w", err)
	}
	return nil
}

type clientCertificate struct {
	certPEM  string
	keyPEM   string
	notAfter time.Time
}

// loadClientCertificate returns nil if no file is given.
// The files are read on every call so that a renewed certificate is picked up.
func loadClientCertificate(certFile, keyFile string) (*clientCertificate, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid key pair: %w", err)
	}
	return &clientCertificate{certPEM: string(certPEM), keyPEM: string(keyPEM), notAfter: pair.Leaf.NotAfter}, nil
}

// apply sets the certificate to the output.
// client-go runs the plugin again only after the expiry, so the expiry must not exceed the certificate lifetime.
func (c *clientCertificate) apply(out *credentialplugin.Output) {
	if c == nil {
		return
	}
	out.ClientCertificateData = c.certPEM
	out.ClientKeyData = c.keyPEM
	if c.notAfter.Before(out.Expiry) {
		out.Expiry = c.notAfter
	}
}
