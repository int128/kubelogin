package config

import "time"

// Want represents a set of expected values.
type Want struct {
	Scope               string
	RedirectURIPrefix   string
	CodeChallengeMethod string            // optional
	ExtraParams         map[string]string // optional
	Username            string            // optional
	Password            string            // optional
	RefreshToken        string            // optional
}

// Response represents a set of response values.
type Response struct {
	IDTokenExpiry                 time.Time
	RefreshToken                  string
	RefreshError                  string   // if set, Refresh() will return the error
	CodeChallengeMethodsSupported []string // optional
}

// Config represents a configuration of the OpenID Connect provider.
type Config struct {
	Want     Want
	Response Response
}
