package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/int128/kubelogin/pkg/adaptors"
	"golang.org/x/xerrors"
)

type Decoder struct{}

// DecodeIDToken returns the claims of the ID token.
// Note that this method does not verify the signature and always trust it.
func (d *Decoder) DecodeIDToken(t string) (*adaptors.DecodedIDToken, error) {
	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return nil, xerrors.Errorf("token contains an invalid number of segments")
	}
	b, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return nil, xerrors.Errorf("could not decode the token: %w", err)
	}
	var claims jwt.StandardClaims
	if err := json.NewDecoder(bytes.NewBuffer(b)).Decode(&claims); err != nil {
		return nil, xerrors.Errorf("could not decode the json of token: %w", err)
	}
	var rawClaims map[string]interface{}
	if err := json.NewDecoder(bytes.NewBuffer(b)).Decode(&rawClaims); err != nil {
		return nil, xerrors.Errorf("could not decode the json of token: %w", err)
	}
	return &adaptors.DecodedIDToken{
		IDTokenExpiry: time.Unix(claims.ExpiresAt, 0),
		IDTokenClaims: dumpRawClaims(rawClaims),
	}, nil
}

func dumpRawClaims(rawClaims map[string]interface{}) map[string]string {
	claims := make(map[string]string)
	for k, v := range rawClaims {
		switch v.(type) {
		case float64:
			claims[k] = fmt.Sprintf("%.f", v.(float64))
		default:
			claims[k] = fmt.Sprintf("%v", v)
		}
	}
	return claims
}
