package pkce

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNew(t *testing.T) {
	t.Run("S256", func(t *testing.T) {
		params, err := New(MethodS256)
		if err != nil {
			t.Fatalf("New error: %s", err)
		}
		if params.CodeChallengeMethod != "S256" {
			t.Errorf("CodeChallengeMethod wants S256 but was %s", params.CodeChallengeMethod)
		}
		if params.CodeChallenge == "" {
			t.Errorf("CodeChallenge wants non-empty but was empty")
		}
		if params.CodeVerifier == "" {
			t.Errorf("CodeVerifier wants non-empty but was empty")
		}
	})
	t.Run("NoMethod", func(t *testing.T) {
		params, err := New(NoMethod)
		if err != nil {
			t.Fatalf("New error: %s", err)
		}
		if diff := cmp.Diff(Params{}, params); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

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
