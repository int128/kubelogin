package jwt

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestDecode(t *testing.T) {
	t.Run("ValidToken", func(t *testing.T) {
		const (
			// https://tools.ietf.org/html/rfc7519#section-3.1
			header    = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
			payload   = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
			signature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
			token     = header + "." + payload + "." + signature
		)
		got, err := DecodeWithoutVerify(token)
		if err != nil {
			t.Fatalf("Decode error: %s", err)
		}
		want := &Claims{
			Subject: "",
			Expiry:  time.Unix(1300819380, 0),
			Pretty: `{
  "iss": "joe",
  "exp": 1300819380,
  "http://example.com/is_root": true
}`,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		decodedToken, err := DecodeWithoutVerify("HEADER.INVALID_TOKEN.SIGNATURE")
		if err == nil {
			t.Errorf("error wants non-nil but nil")
		} else {
			t.Logf("expected error: %+v", err)
		}
		if decodedToken != nil {
			t.Errorf("decodedToken wants nil but %+v", decodedToken)
		}
	})
}
