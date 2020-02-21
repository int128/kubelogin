package jwt

import "time"

// Claims represents claims of an ID token.
type Claims struct {
	Subject string
	Expiry  time.Time
	Pretty  string // string representation for debug and logging
}

// Clock provides the current time.
type Clock interface {
	Now() time.Time
}

// IsExpired returns true if the token is expired.
func (c *Claims) IsExpired(clock Clock) bool {
	return c.Expiry.Before(clock.Now())
}
