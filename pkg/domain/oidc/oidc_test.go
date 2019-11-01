package oidc

import (
	"testing"
)

func Test_computeS256(t *testing.T) {
	// Testdata described at:
	// https://tools.ietf.org/html/rfc7636#appendix-B
	b := []byte{
		116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
		187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
		132, 141, 121,
	}
	p := computeS256(b)
	if want := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; want != p.CodeVerifier {
		t.Errorf("CodeVerifier wants %s but was %s", want, p.CodeVerifier)
	}
	if want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; want != p.CodeChallenge {
		t.Errorf("CodeChallenge wants %s but was %s", want, p.CodeChallenge)
	}
	if p.CodeChallengeMethod != "S256" {
		t.Errorf("CodeChallengeMethod wants S256 but was %s", p.CodeChallengeMethod)
	}
}
