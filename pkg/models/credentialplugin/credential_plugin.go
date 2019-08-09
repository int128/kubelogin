// Package credentialplugin provides models for the credential plugin.
package credentialplugin

import "time"

// TokenCache represents a token object cached.
type TokenCache struct {
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Output represents an output object of the credential plugin.
type Output struct {
	Token  string
	Expiry time.Time
}
