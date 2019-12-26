package oidc

import "time"

// Claims represents claims of an ID token.
type Claims struct {
	Subject string
	Expiry  time.Time
	Pretty  map[string]string // string representation for debug and logging
}
