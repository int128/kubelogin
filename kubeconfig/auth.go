package kubeconfig

import "k8s.io/client-go/tools/clientcmd/api"

// FindCurrentAuthInfo returns the authInfo of current context.
func FindCurrentAuthInfo(config *api.Config) *api.AuthInfo {
	context := config.Contexts[config.CurrentContext]
	if context == nil {
		return nil
	}
	return config.AuthInfos[context.AuthInfo]
}
