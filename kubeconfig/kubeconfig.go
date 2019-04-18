// Package kubeconfig provides the models of kuneconfig file.
package kubeconfig

import (
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd/api"
)

// KubeConfig represents a config.
type KubeConfig api.Config

// FindContext returns the context.
// If the context does not exist, this returns an error.
func (c *KubeConfig) FindContext(name string) (*KubeContext, error) {
	contextNode := c.Contexts[name]
	if contextNode == nil {
		return nil, errors.Errorf("context %s does not exist", name)
	}
	return (*KubeContext)(contextNode), nil
}

// DeepCopy returns a deep copy.
func (c *KubeConfig) DeepCopy() *KubeConfig {
	return (*KubeConfig)((*api.Config)(c).DeepCopy())
}

// FindOIDCAuthProvider returns the OIDC auth-provider.
//
// If the auth-info or auth-provider does not exist, this returns an error.
// If auth-provider is not "oidc", this returns an error.
func (c *KubeConfig) FindOIDCAuthProvider(authInfoName string) (*OIDCAuthProvider, error) {
	authInfoNode := c.AuthInfos[authInfoName]
	if authInfoNode == nil {
		return nil, errors.Errorf("user %s does not exist", authInfoName)
	}
	if authInfoNode.AuthProvider == nil {
		return nil, errors.Errorf("auth-provider is not set")
	}
	if authInfoNode.AuthProvider.Name != "oidc" {
		return nil, errors.Errorf("auth-provider must be oidc but was %s", authInfoNode.AuthProvider.Name)
	}
	return (*OIDCAuthProvider)(authInfoNode.AuthProvider), nil
}

type KubeContext api.Context
