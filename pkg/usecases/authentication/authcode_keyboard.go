package authentication

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/reader"
	"github.com/int128/kubelogin/pkg/domain/oidc"
	"golang.org/x/xerrors"
)

const authCodeKeyboardPrompt = "Enter code: "
const oobRedirectURI = "urn:ietf:wg:oauth:2.0:oob"

// AuthCodeKeyboard provides the authorization code flow with keyboard interactive.
type AuthCodeKeyboard struct {
	Reader reader.Interface
	Logger logger.Interface
}

func (u *AuthCodeKeyboard) Do(ctx context.Context, _ *AuthCodeKeyboardOption, client oidcclient.Interface) (*Output, error) {
	u.Logger.V(1).Infof("performing the authorization code flow with keyboard interactive")
	state, err := oidc.NewState()
	if err != nil {
		return nil, xerrors.Errorf("could not generate a state: %w", err)
	}
	nonce, err := oidc.NewNonce()
	if err != nil {
		return nil, xerrors.Errorf("could not generate a nonce: %w", err)
	}
	p, err := oidc.NewPKCEParams()
	if err != nil {
		return nil, xerrors.Errorf("could not generate PKCE parameters: %w", err)
	}
	authCodeURL := client.GetAuthCodeURL(oidcclient.AuthCodeURLInput{
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
		RedirectURI:         oobRedirectURI,
	})
	u.Logger.Printf("Open %s", authCodeURL)
	code, err := u.Reader.ReadString(authCodeKeyboardPrompt)
	if err != nil {
		return nil, xerrors.Errorf("could not read an authorization code: %w", err)
	}

	tokenSet, err := client.ExchangeAuthCode(ctx, oidcclient.ExchangeAuthCodeInput{
		Code:         code,
		CodeVerifier: p.CodeVerifier,
		Nonce:        nonce,
		RedirectURI:  oobRedirectURI,
	})
	if err != nil {
		return nil, xerrors.Errorf("could not exchange the authorization code: %w", err)
	}
	return &Output{
		IDToken:       tokenSet.IDToken,
		IDTokenClaims: tokenSet.IDTokenClaims,
		RefreshToken:  tokenSet.RefreshToken,
	}, nil
}
