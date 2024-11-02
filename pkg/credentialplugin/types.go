// Package credentialplugin provides the types for client-go credential plugins.
package credentialplugin

import "time"

// Input represents an input object of the credential plugin.
// This may be a zero value if the input is not available.
type Input struct {
	ClientAuthenticationAPIVersion string
}

// Output represents an output object of the credential plugin.
type Output struct {
	Token                          string
	Expiry                         time.Time
	ClientAuthenticationAPIVersion string
}
