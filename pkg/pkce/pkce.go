// Package pkce provides generation of the PKCE parameters.
// See also https://tools.ietf.org/html/rfc7636.
package pkce

import "golang.org/x/oauth2"

type Method int

const (
	// Code challenge methods defined as https://tools.ietf.org/html/rfc7636#section-4.3
	NoMethod Method = iota
	MethodS256
)

// Params represents a set of the PKCE parameters.
type Params struct {
	Method   Method
	Verifier string
}

func (params Params) AuthCodeOption() oauth2.AuthCodeOption {
	if params.Method == MethodS256 {
		return oauth2.S256ChallengeOption(params.Verifier)
	}
	return nil
}

func (params Params) TokenRequestOption() oauth2.AuthCodeOption {
	if params.Method == MethodS256 {
		return oauth2.VerifierOption(params.Verifier)
	}
	return nil
}

// New returns a parameters supported by the provider.
// You need to pass the code challenge methods defined in RFC7636.
// It returns a zero value if no method is available.
func New(method Method) (Params, error) {
	if method == MethodS256 {
		return Params{
			Method:   MethodS256,
			Verifier: oauth2.GenerateVerifier(),
		}, nil
	}
	return Params{}, nil
}
