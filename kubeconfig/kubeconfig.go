// Package kubeconfig provides the models of kubeconfig file.
package kubeconfig

import (
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd/api"
)

type ContextName string
type UserName string

// Config represents a config.
type Config api.Config

// Context represents a context.
type Context api.Context

// User represents a user.
type User api.AuthInfo

// CurrentAuth represents the current authentication, that is,
// context, user and auth-provider.
type CurrentAuth struct {
	ContextName ContextName // empty if UserName is given
	Context     *Context    // nil if UserName is given
	UserName    UserName
	User        *User
	OIDCConfig  OIDCConfig
}

// FindCurrentAuth resolves the current context and user.
// If contextName is given, this returns the user of the context.
// If userName is given, this ignores the context and returns the user.
// If any context or user is not found, this returns an error.
func FindCurrentAuth(config *Config, contextName ContextName, userName UserName) (*CurrentAuth, error) {
	var kubeContext *Context
	if userName == "" {
		if contextName == "" {
			contextName = ContextName(config.CurrentContext)
		}
		contextNode := config.Contexts[string(contextName)]
		if contextNode == nil {
			return nil, errors.Errorf("context %s does not exist", contextName)
		}
		kubeContext = (*Context)(contextNode)
		userName = UserName(kubeContext.AuthInfo)
	}
	userNode := config.AuthInfos[string(userName)]
	if userNode == nil {
		return nil, errors.Errorf("user %s does not exist", userName)
	}
	user := (*User)(userNode)
	if user.AuthProvider == nil {
		return nil, errors.Errorf("auth-provider is missing")
	}
	if user.AuthProvider.Name != "oidc" {
		return nil, errors.Errorf("auth-provider must be oidc but is %s", user.AuthProvider.Name)
	}
	return &CurrentAuth{
		ContextName: contextName,
		Context:     kubeContext,
		UserName:    userName,
		User:        user,
		OIDCConfig:  user.AuthProvider.Config,
	}, nil
}
