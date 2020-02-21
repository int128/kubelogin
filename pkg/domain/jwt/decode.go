// Package jwt provides JWT manipulations.
// See https://tools.ietf.org/html/rfc7519#section-4.1.3
package jwt

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/xerrors"
)

// DecodeWithoutVerify decodes the JWT string and returns the claims.
// Note that this method does not verify the signature and always trust it.
func DecodeWithoutVerify(s string) (*Claims, error) {
	payload, err := DecodePayload(s)
	if err != nil {
		return nil, xerrors.Errorf("could not decode the payload: %w", err)
	}
	var claims struct {
		Subject   string `json:"sub,omitempty"`
		ExpiresAt int64  `json:"exp,omitempty"`
	}
	if err := json.NewDecoder(bytes.NewReader(payload)).Decode(&claims); err != nil {
		return nil, xerrors.Errorf("could not decode the json of token: %w", err)
	}
	var prettyJson bytes.Buffer
	if err := json.Indent(&prettyJson, payload, "", "  "); err != nil {
		return nil, xerrors.Errorf("could not indent the json of token: %w", err)
	}
	return &Claims{
		Subject: claims.Subject,
		Expiry:  time.Unix(claims.ExpiresAt, 0),
		Pretty:  prettyJson.String(),
	}, nil
}

// DecodePayload extracts the payload and decodes base64.
func DecodePayload(s string) ([]byte, error) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return nil, xerrors.Errorf("token contains an invalid number of segments")
	}
	rawJSON, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return nil, xerrors.Errorf("could not decode json: %w", err)
	}
	return rawJSON, nil
}
