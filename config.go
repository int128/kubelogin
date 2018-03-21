package main

import (
	"os"

	"github.com/mitchellh/go-homedir"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// GetCurrentAuthInfo returns the current authInfo
func GetCurrentAuthInfo(config api.Config) *api.AuthInfo {
	context := config.Contexts[config.CurrentContext]
	if context == nil {
		return nil
	}
	authInfo := config.AuthInfos[context.AuthInfo]
	return authInfo
}

// ReadKubeConfig returns the current config
func ReadKubeConfig(path string) (*api.Config, error) {
	config, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// WriteKubeConfig writes the config
func WriteKubeConfig(config api.Config, path string) error {
	return clientcmd.WriteToFile(config, path)
}

// FindKubeConfig returns env:KUBECONFIG or ~/.kube/config
func FindKubeConfig() (string, error) {
	env := os.Getenv("KUBECONFIG")
	if env != "" {
		return env, nil
	}
	path, err := homedir.Expand("~/.kube/config")
	if err != nil {
		return "", err
	}
	return path, nil
}
