package jwt

import "time"

// Claims represents claims of an ID token.
type Claims struct {
	Subject string
	Expiry  time.Time
	Pretty  string // string representation for debug and logging
}

// TimeProvider provides the current time.
type TimeProvider interface {
	Now() time.Time
}

// IsExpired returns true if the token is expired.
func (c *Claims) IsExpired(timeProvider TimeProvider) bool {
	return c.Expiry.Before(timeProvider.Now())
}
