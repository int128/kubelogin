package authz

import (
	"context"

	"golang.org/x/oauth2"
)

// Flow represents an authorization method.
type Flow interface {
	GetToken(context.Context) (*oauth2.Token, error)
}
