// Token types defined in RFC 8693. Defines token "formats" and "purposes"
// https://datatracker.ietf.org/doc/html/rfc8693#name-token-type-identifiers
package identifiers

import (
	"fmt"
	"strings"
)

const AccessTokenType = "urn:ietf:params:oauth:token-type:access_token"
const RefreshTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
const IDTokenType = "urn:ietf:params:oauth:token-type:id_token"

const SAML1TokenType = "urn:ietf:params:oauth:token-type:saml1"
const SAML2TokenType = "urn:ietf:params:oauth:token-type:saml2"
const JWTTokenType = "urn:ietf:params:oauth:token-type:jwt"

// Given a string like "refresh-token", return "urn:ietf:params:oauth:token-type:refresh_token"
// Return the same string if already in canonical format.
// if the input string is not a known type, return an error
func CanonicalTokenType(s string) (string, error) {
	known_types := []string{
		AccessTokenType,
		RefreshTokenType,
		IDTokenType,
		SAML1TokenType,
		SAML2TokenType,
		JWTTokenType,
	}

	for _, t := range known_types {
		if s == t {
			return t, nil
		}

		// refresh-token -> refresh_token
		s = strings.Replace(s, "-", "_", -1)
		if fmt.Sprintf("urn:ietf:params:oauth:token-type:%s", s) == t {
			return t, nil
		}
	}

	return "", fmt.Errorf("unknown token type: %s", s)
}
