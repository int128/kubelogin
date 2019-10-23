package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/xerrors"
)

type DecoderInterface interface {
	DecodeIDToken(t string) (*DecodedIDToken, error)
}

type DecodedIDToken struct {
	Subject string
	Expiry  time.Time
	Claims  map[string]string // string representation of claims for logging
}

type Decoder struct{}

// DecodeIDToken returns the claims of the ID token.
// Note that this method does not verify the signature and always trust it.
func (d *Decoder) DecodeIDToken(t string) (*DecodedIDToken, error) {
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
	return &DecodedIDToken{
		Subject: claims.Subject,
		Expiry:  time.Unix(claims.ExpiresAt, 0),
		Claims:  dumpRawClaims(rawClaims),
	}, nil
}

func dumpRawClaims(rawClaims map[string]interface{}) map[string]string {
	claims := make(map[string]string)
	for k, v := range rawClaims {
		switch v := v.(type) {
		case float64:
			claims[k] = fmt.Sprintf("%.f", v)
		default:
			claims[k] = fmt.Sprintf("%v", v)
		}
	}
	return claims
}
