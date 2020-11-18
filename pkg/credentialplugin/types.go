// Package credentialplugin provides the types for client-go credential plugins.
package credentialplugin

import "time"

// Output represents an output object of the credential plugin.
type Output struct {
	Token  string
	Expiry time.Time
}
