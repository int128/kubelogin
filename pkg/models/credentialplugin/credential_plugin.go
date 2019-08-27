// Package credentialplugin provides models for the credential plugin.
package credentialplugin

// TokenCacheKey represents a key of a token cache.
type TokenCacheKey struct {
	IssuerURL string
	ClientID  string
}

// TokenCache represents a token cache.
type TokenCache struct {
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
