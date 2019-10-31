package authentication

import (
	"context"
	"time"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/jwtdecoder"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_authentication/mock_authentication.go github.com/int128/kubelogin/pkg/usecases/authentication Interface

// Set provides the use-case of Authentication.
var Set = wire.NewSet(
	wire.Struct(new(Authentication), "*"),
	wire.Bind(new(Interface), new(*Authentication)),
)

// LocalServerReadyFunc provides an extension point for e2e tests.
type LocalServerReadyFunc func(url string)

// DefaultLocalServerReadyFunc is the default noop function.
var DefaultLocalServerReadyFunc = LocalServerReadyFunc(nil)

type Interface interface {
	Do(ctx context.Context, in Input) (*Output, error)
}

// Input represents an input DTO of the Authentication use-case.
type Input struct {
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	ExtraScopes    []string // optional
	CertPool       certpool.Interface
	SkipTLSVerify  bool
	IDToken        string // optional
	RefreshToken   string // optional
	GrantOptionSet GrantOptionSet
}

type GrantOptionSet struct {
	AuthCodeOption *AuthCodeOption
	ROPCOption     *ROPCOption
}

type AuthCodeOption struct {
	SkipOpenBrowser bool
	BindAddress     []string
}

type ROPCOption struct {
	Username string
	Password string // If empty, read a password using Env.ReadPassword()
}

// Output represents an output DTO of the Authentication use-case.
type Output struct {
	AlreadyHasValidIDToken bool
	IDTokenSubject         string
	IDTokenExpiry          time.Time
	IDTokenClaims          map[string]string
	IDToken                string
	RefreshToken           string
}

const usernamePrompt = "Username: "
const passwordPrompt = "Password: "

// Authentication provides the internal use-case of authentication.
//
// If the IDToken is not set, it performs the authentication flow.
// If the IDToken is valid, it does nothing.
// If the IDtoken has expired and the RefreshToken is set, it refreshes the token.
// If the RefreshToken has expired, it performs the authentication flow.
//
// The authentication flow is determined as:
//
// If the Username is not set, it performs the authorization code flow.
// Otherwise, it performs the resource owner password credentials flow.
// If the Password is not set, it asks a password by the prompt.
//
type Authentication struct {
	OIDCClientFactory    oidcclient.FactoryInterface
	JWTDecoder           jwtdecoder.Interface
	Env                  env.Interface
	Logger               logger.Interface
	LocalServerReadyFunc LocalServerReadyFunc // only for e2e tests
}

func (u *Authentication) Do(ctx context.Context, in Input) (*Output, error) {
	if in.IDToken != "" {
		u.Logger.V(1).Infof("checking expiration of the existing token")
		// Skip verification of the token to reduce time of a discovery request.
		// Here it trusts the signature and claims and checks only expiration,
		// because the token has been verified before caching.
		claims, err := u.JWTDecoder.Decode(in.IDToken)
		if err != nil {
			return nil, xerrors.Errorf("invalid token and you need to remove the cache: %w", err)
		}
		if claims.Expiry.After(time.Now()) { //TODO: inject time service
			u.Logger.V(1).Infof("you already have a valid token until %s", claims.Expiry)
			return &Output{
				AlreadyHasValidIDToken: true,
				IDToken:                in.IDToken,
				RefreshToken:           in.RefreshToken,
				IDTokenSubject:         claims.Subject,
				IDTokenExpiry:          claims.Expiry,
				IDTokenClaims:          claims.Pretty,
			}, nil
		}
		u.Logger.V(1).Infof("you have an expired token at %s", claims.Expiry)
	}

	u.Logger.V(1).Infof("initializing an OpenID Connect client")
	client, err := u.OIDCClientFactory.New(ctx, oidcclient.Config{
		IssuerURL:     in.IssuerURL,
		ClientID:      in.ClientID,
		ClientSecret:  in.ClientSecret,
		ExtraScopes:   in.ExtraScopes,
		CertPool:      in.CertPool,
		SkipTLSVerify: in.SkipTLSVerify,
	})
	if err != nil {
		return nil, xerrors.Errorf("could not create an OpenID Connect client: %w", err)
	}

	if in.RefreshToken != "" {
		u.Logger.V(1).Infof("refreshing the token")
		out, err := client.Refresh(ctx, in.RefreshToken)
		if err == nil {
			return &Output{
				IDToken:        out.IDToken,
				RefreshToken:   out.RefreshToken,
				IDTokenSubject: out.IDTokenSubject,
				IDTokenExpiry:  out.IDTokenExpiry,
				IDTokenClaims:  out.IDTokenClaims,
			}, nil
		}
		u.Logger.V(1).Infof("could not refresh the token: %s", err)
	}

	if in.GrantOptionSet.AuthCodeOption != nil {
		return u.doAuthCodeFlow(ctx, in.GrantOptionSet.AuthCodeOption, client)
	}
	if in.GrantOptionSet.ROPCOption != nil {
		return u.doPasswordCredentialsFlow(ctx, in.GrantOptionSet.ROPCOption, client)
	}
	return nil, xerrors.Errorf("any authorization grant must be set")
}

func (u *Authentication) doAuthCodeFlow(ctx context.Context, in *AuthCodeOption, client oidcclient.Interface) (*Output, error) {
	u.Logger.V(1).Infof("performing the authentication code flow")
	readyChan := make(chan string, 1)
	defer close(readyChan)
	var out Output
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		select {
		case url, ok := <-readyChan:
			if !ok {
				return nil
			}
			u.Logger.Printf("Open %s for authentication", url)
			if u.LocalServerReadyFunc != nil {
				u.LocalServerReadyFunc(url)
			}
			if in.SkipOpenBrowser {
				return nil
			}
			if err := u.Env.OpenBrowser(url); err != nil {
				u.Logger.V(1).Infof("could not open the browser: %s", err)
			}
			return nil
		case <-ctx.Done():
			return xerrors.Errorf("context cancelled while waiting for the local server: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		tokenSet, err := client.AuthenticateByCode(ctx, in.BindAddress, readyChan)
		if err != nil {
			return xerrors.Errorf("error while the authorization code flow: %w", err)
		}
		out = Output{
			IDToken:        tokenSet.IDToken,
			RefreshToken:   tokenSet.RefreshToken,
			IDTokenSubject: tokenSet.IDTokenSubject,
			IDTokenExpiry:  tokenSet.IDTokenExpiry,
			IDTokenClaims:  tokenSet.IDTokenClaims,
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, xerrors.Errorf("error while the authorization code flow: %w", err)
	}
	return &out, nil
}

func (u *Authentication) doPasswordCredentialsFlow(ctx context.Context, in *ROPCOption, client oidcclient.Interface) (*Output, error) {
	u.Logger.V(1).Infof("performing the resource owner password credentials flow")
	if in.Username == "" {
		var err error
		in.Username, err = u.Env.ReadString(usernamePrompt)
		if err != nil {
			return nil, xerrors.Errorf("could not get the username: %w", err)
		}
	}
	if in.Password == "" {
		var err error
		in.Password, err = u.Env.ReadPassword(passwordPrompt)
		if err != nil {
			return nil, xerrors.Errorf("could not read a password: %w", err)
		}
	}
	tokenSet, err := client.AuthenticateByPassword(ctx, in.Username, in.Password)
	if err != nil {
		return nil, xerrors.Errorf("error while the resource owner password credentials flow: %w", err)
	}
	return &Output{
		IDToken:        tokenSet.IDToken,
		RefreshToken:   tokenSet.RefreshToken,
		IDTokenSubject: tokenSet.IDTokenSubject,
		IDTokenExpiry:  tokenSet.IDTokenExpiry,
		IDTokenClaims:  tokenSet.IDTokenClaims,
	}, nil
}
